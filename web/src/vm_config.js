        // ═══════════════════════════════════════════════
        // PegaProx - VM Configuration
        // ConfigModal, disk/network/ISO management
        // ═══════════════════════════════════════════════
        // VM/Container Config Modal
        // LW: This is the big one - handles all VM/CT configuration
        // Tabs: General, Hardware (disks/NICs), Options, Snapshots, Replication
        // Sep 2025: Major refactor to support both QEMU and LXC properly

        // IP Set entries sub-component for VM Firewall
        function IpsetEntries({ clusterId, vm, ipsetName, authFetch, onRefresh, t }) {
            const [entries, setEntries] = useState([]);
            const [loading, setLoading] = useState(true);
            const [newCidr, setNewCidr] = useState('');

            useEffect(() => {
                loadEntries();
            }, [ipsetName]);

            const loadEntries = async () => {
                setLoading(true);
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/ipset/${ipsetName}`);
                    if (res?.ok) setEntries(await res.json());
                } catch (e) {}
                setLoading(false);
            };

            return (
                <div className="p-4">
                    {loading ? (
                        <div className="flex justify-center py-4">
                            <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-proxmox-orange"></div>
                        </div>
                    ) : (
                        <>
                            <div className="flex gap-2 mb-3">
                                <input
                                    type="text"
                                    value={newCidr}
                                    onChange={e => setNewCidr(e.target.value)}
                                    placeholder="e.g. 10.0.0.0/24"
                                    className="flex-1 bg-proxmox-dark border border-proxmox-border rounded-lg px-3 py-1.5 text-sm"
                                    onKeyDown={async (e) => {
                                        if (e.key === 'Enter' && newCidr) {
                                            try {
                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/ipset/${ipsetName}`, {
                                                    method: 'POST',
                                                    headers: { 'Content-Type': 'application/json' },
                                                    body: JSON.stringify({ cidr: newCidr })
                                                });
                                                if (res?.ok) { loadEntries(); setNewCidr(''); }
                                            } catch (e) {}
                                        }
                                    }}
                                />
                                <button
                                    onClick={async () => {
                                        if (!newCidr) return;
                                        try {
                                            const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/ipset/${ipsetName}`, {
                                                method: 'POST',
                                                headers: { 'Content-Type': 'application/json' },
                                                body: JSON.stringify({ cidr: newCidr })
                                            });
                                            if (res?.ok) { loadEntries(); setNewCidr(''); }
                                        } catch (e) {}
                                    }}
                                    className="px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white transition-colors"
                                >
                                    {t('add')}
                                </button>
                            </div>
                            {entries.length === 0 ? (
                                <div className="text-center text-gray-500 py-4 text-sm">Empty set</div>
                            ) : (
                                <div className="space-y-1">
                                    {entries.map((entry, idx) => (
                                        <div key={idx} className="flex justify-between items-center p-2 bg-proxmox-dark rounded-lg">
                                            <span className="font-mono text-sm">{entry.cidr}</span>
                                            <div className="flex items-center gap-2">
                                                {entry.comment && <span className="text-gray-500 text-xs">{entry.comment}</span>}
                                                <button
                                                    onClick={async () => {
                                                        try {
                                                            const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/ipset/${ipsetName}/${encodeURIComponent(entry.cidr)}`, { method: 'DELETE' });
                                                            if (res?.ok) loadEntries();
                                                        } catch (e) {}
                                                    }}
                                                    className="p-1 hover:bg-red-500/20 rounded text-red-400 transition-colors"
                                                >
                                                    <Icons.Trash className="w-3.5 h-3.5" />
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </>
                    )}
                </div>
            );
        }

        function ConfigModal({ vm, clusterId, allClusters = [], dashboardAuthFetch, onClose, addToast }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [config, setConfig] = useState(null);
            const [configError, setConfigError] = useState(null);  // MK: Track config load errors
            const [loading, setLoading] = useState(true);
            const [saving, setSaving] = useState(false);
            const [activeTab, setActiveTab] = useState('general');
            const [changes, setChanges] = useState({});
            const [hasChanges, setHasChanges] = useState(false);
            
            // Additional states for hardware options and lists
            const [hardwareOptions, setHardwareOptions] = useState(null);
            const [storageList, setStorageList] = useState([]);
            const [bridgeList, setBridgeList] = useState([]);
            const [isoList, setIsoList] = useState([]);
            
            // Snapshot states
            const [snapshots, setSnapshots] = useState([]);
            const [snapshotLoading, setSnapshotLoading] = useState(false);
            const [showCreateSnapshot, setShowCreateSnapshot] = useState(false);

            // NS: Feb 2026 - Efficient snapshot states
            const [efficientSnapshots, setEfficientSnapshots] = useState([]);
            const [efficientInfo, setEfficientInfo] = useState(null);

            // Replication states
            const [replications, setReplications] = useState([]);
            
            // NS: Backup states - Dec 2025
            const [vmBackups, setVmBackups] = useState([]);
            const [backupLoading, setBackupLoading] = useState(false);
            const [showCreateBackup, setShowCreateBackup] = useState(false);
            const [showRestoreBackup, setShowRestoreBackup] = useState(null);
            
            // MK: History states - Jan 2026
            const [vmProxmoxTasks, setVmProxmoxTasks] = useState([]);
            const [vmPegaproxActions, setVmPegaproxActions] = useState([]);
            const [historyLoading, setHistoryLoading] = useState(false);
            const [historySubTab, setHistorySubTab] = useState('proxmox');
            
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
            const [replicationLoading, setReplicationLoading] = useState(false);
            const [showCreateReplication, setShowCreateReplication] = useState(false);
            const [clusterNodes, setClusterNodes] = useState([]);
            const [allClusterNodes, setAllClusterNodes] = useState([]);
            const [crossClusterRepls, setCrossClusterRepls] = useState([]); // MK: cross-cluster DR jobs
            const [showCreateXRepl, setShowCreateXRepl] = useState(false);
            const [xReplForm, setXReplForm] = useState({ target_cluster: '', target_storage: '', target_bridge: 'vmbr0', schedule: '0 */6 * * *', retention: 3 });
            // NS: Target cluster resources for cross-cluster replication dropdowns
            const [xReplTargetStorages, setXReplTargetStorages] = useState([]);
            const [xReplTargetBridges, setXReplTargetBridges] = useState([]);
            const [xReplLoadingResources, setXReplLoadingResources] = useState(false);
            
            // Modal states for sub-dialogs
            const [showAddDisk, setShowAddDisk] = useState(false);
            const [showAddNetwork, setShowAddNetwork] = useState(false);
            const [showEditNetwork, setShowEditNetwork] = useState(null);
            const [showMoveDisk, setShowMoveDisk] = useState(null);
            const [showResizeDisk, setShowResizeDisk] = useState(null);
            const [showEditDisk, setShowEditDisk] = useState(null);  // NS: Edit disk bus type
            const [showReattachDisk, setShowReattachDisk] = useState(null);  // MK: Reattach unused disk modal
            const [showMountISO, setShowMountISO] = useState(false);
            const [showImportDisk, setShowImportDisk] = useState(false);  // MK: Import disk from storage
            const [showReassignOwner, setShowReassignOwner] = useState(null);  // MK: Reassign disk to another VM
            const [importableDisks, setImportableDisks] = useState([]);  // MK: List of importable disk images
            
            // PCI/USB/Serial Passthrough states
            const [passthrough, setPassthrough] = useState({ pci: [], usb: [], serial: [] });
            const [availablePci, setAvailablePci] = useState([]);
            const [availableUsb, setAvailableUsb] = useState([]);
            const [showAddPci, setShowAddPci] = useState(false);
            const [showAddUsb, setShowAddUsb] = useState(false);
            const [showAddSerial, setShowAddSerial] = useState(false);
            const [showAddEfiDisk, setShowAddEfiDisk] = useState(false);  // NS: EFI Disk modal
            const [showAddTpm, setShowAddTpm] = useState(false);          // NS: TPM modal
            const [efiStorage, setEfiStorage] = useState('');             // NS: Selected storage for EFI
            const [tpmStorage, setTpmStorage] = useState('');             // NS: Selected storage for TPM
            const [selectedPciDevice, setSelectedPciDevice] = useState(null);
            const [selectedUsbDevice, setSelectedUsbDevice] = useState(null);
            const [pciOptions, setPciOptions] = useState({ pcie: true, rombar: true });
            const [usbOptions, setUsbOptions] = useState({ usb3: false });
            const [serialType, setSerialType] = useState('socket');
            const [passthroughLoading, setPassthroughLoading] = useState(false);

            // Firewall states
            const [fwOptions, setFwOptions] = useState({});
            const [fwRules, setFwRules] = useState([]);
            const [fwAliases, setFwAliases] = useState([]);
            const [fwIpsets, setFwIpsets] = useState([]);
            const [fwLog, setFwLog] = useState([]);
            const [fwRefs, setFwRefs] = useState([]);
            const [fwLoading, setFwLoading] = useState(false);
            const [showAddFwRule, setShowAddFwRule] = useState(false);
            const [newFwRule, setNewFwRule] = useState({ type: 'in', action: 'ACCEPT', enable: 1 });
            const [showAddFwAlias, setShowAddFwAlias] = useState(false);
            const [newFwAlias, setNewFwAlias] = useState({ name: '', cidr: '', comment: '' });
            const [showAddFwIpset, setShowAddFwIpset] = useState(false);
            const [newFwIpset, setNewFwIpset] = useState({ name: '', comment: '' });
            const [expandedIpset, setExpandedIpset] = useState(null);
            const [newIpsetCidr, setNewIpsetCidr] = useState('');
            const [fwSubTab, setFwSubTab] = useState('rules');

            const isQemu = vm.type === 'qemu';

            useEffect(() => {
                fetchConfig();
                fetchHardwareOptions();
                fetchStorageList();
                fetchBridgeList();
                if (isQemu) {
                    fetchISOList();
                    fetchPassthrough();
                }
                fetchSnapshots();
                fetchEfficientSnapshots();
                fetchEfficientInfo();
                fetchReplications();
                fetchCrossClusterRepls();
                fetchBackups();
                fetchClusterNodes();
                
                // NS: Listen for SSE vm_config events for live updates
                const handleVmConfigUpdate = (event) => {
                    const { vmid: eventVmid, vm_type, config: newConfig } = event.detail;
                    // Only update if this is our VM and user has no pending changes
                    if (eventVmid === vm.vmid && vm_type === vm.type && !hasChanges && !saving) {
                        console.log('SSE: Updating config for', vm.vmid);
                        setConfig(prev => ({
                            ...prev,
                            ...newConfig,
                            // Preserve some local state
                            disks: newConfig.disks || prev?.disks,
                            unused_disks: newConfig.unused_disks || prev?.unused_disks,
                            options: {
                                ...prev?.options,
                                ...newConfig.options
                            },
                            raw: {
                                ...prev?.raw,
                                ...newConfig.raw
                            }
                        }));
                    }
                };
                
                window.addEventListener('pegaprox-vm-config', handleVmConfigUpdate);
                return () => window.removeEventListener('pegaprox-vm-config', handleVmConfigUpdate);
            }, [vm, clusterId, hasChanges, saving]);

            // MK: Auto-fetch history when history tab is selected
            useEffect(() => {
                if (activeTab === 'history') {
                    fetchHistory();
                }
            }, [activeTab]);

            useEffect(() => {
                if (activeTab === 'firewall') {
                    fetchFirewallData();
                }
            }, [activeTab]);

            const fetchPassthrough = async () => {
                if (vm.type !== 'qemu') return;
                try {
                    // Fetch current passthrough config
                    const ptRes = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/qemu/${vm.vmid}/passthrough`);
                    if (ptRes && ptRes.ok) {
                        setPassthrough(await ptRes.json());
                    }
                    
                    // Fetch available PCI devices
                    const pciRes = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${vm.node}/hardware/pci`);
                    if (pciRes && pciRes.ok) {
                        setAvailablePci(await pciRes.json());
                    }
                    
                    // Fetch available USB devices
                    const usbRes = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${vm.node}/hardware/usb`);
                    if (usbRes && usbRes.ok) {
                        setAvailableUsb(await usbRes.json());
                    }
                } catch (error) {
                    console.error('to load passthrough:', error);
                }
            };

            const handleAddPciDevice = async () => {
                if (!selectedPciDevice) return;
                setPassthroughLoading(true);
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/qemu/${vm.vmid}/passthrough/pci`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            device_id: selectedPciDevice.id,
                            pcie: pciOptions.pcie,
                            rombar: pciOptions.rombar
                        })
                    });
                    if (response && response.ok) {
                        setShowAddPci(false);
                        setSelectedPciDevice(null);
                        fetchPassthrough();
                        addToast(t('deviceAdded'));
                    }else{
                        const err = await response.json();
                        addToast(err.error || t('operationFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setPassthroughLoading(false);
            };

            const handleAddUsbDevice = async () => {
                if (!selectedUsbDevice) return;
                setPassthroughLoading(true);
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/qemu/${vm.vmid}/passthrough/usb`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            vendorid: selectedUsbDevice.vendid,
                            productid: selectedUsbDevice.prodid,
                            usb3: usbOptions.usb3
                        })
                    });
                    if (response && response.ok) {
                        setShowAddUsb(false);
                        setSelectedUsbDevice(null);
                        fetchPassthrough();
                        addToast(t('deviceAdded'));
                    }else{
                        const err = await response.json();
                        addToast(err.error || t('operationFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setPassthroughLoading(false);
            };

            const handleAddSerialPort = async () => {
                setPassthroughLoading(true);
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/qemu/${vm.vmid}/passthrough/serial`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ type: serialType })
                    });
                    if (response && response.ok) {
                        setShowAddSerial(false);
                        fetchPassthrough();
                        addToast(t('deviceAdded'));
                    }else{
                        const err = await response.json();
                        addToast(err.error || t('operationFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setPassthroughLoading(false);
            };

            const handleRemovePassthrough = async (type, key) => {
                if (!confirm(`${key} ${t('remove')}?`)) return;
                setPassthroughLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/qemu/${vm.vmid}/passthrough/${type}/${key}`,
                        { method: 'DELETE' }
                    );
                    if (response && response.ok) {
                        fetchPassthrough();
                        addToast(t('deviceRemoved'));
                    }else{
                        addToast(t('operationFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setPassthroughLoading(false);
            };

            const fetchConfig = async (retryCount = 0) => {
                setLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`
                    );
                    if (response && response.ok) {
                        const data = await response.json();
                        setConfig(data);
                        setConfigError(null);  // LW: Clear any previous error
                    } else if (response) {
                        // MK: API returned error status
                        const errText = await response.text();
                        setConfigError(t('configLoadError') || 'Could not load configuration');
                        console.error('Config load failed:', errText);
                    }
                } catch (error) {
                    console.error('Failed to load config:', error);
                    // LW: Retry up to 2 times with increasing delay
                    if (retryCount < 2) {
                        setTimeout(() => fetchConfig(retryCount + 1), 1000 * (retryCount + 1));
                        return;
                    }
                    setConfigError(t('configLoadError') || 'Could not load configuration');
                }
                setLoading(false);
            };

            const fetchHardwareOptions = async () => {
                try {
                    const response = await authFetch(`${API_URL}/hardware-options`);
                    if (response && response.ok) {
                        setHardwareOptions(await response.json());
                    }
                } catch (error) {
                    console.error('to load hardware options:', error);
                }
            };

            const fetchStorageList = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${vm.node}/storage`);
                    if (response && response.ok) {
                        setStorageList(await response.json());
                    }
                } catch (error) {
                    console.error('to load storage list:', error);
                }
            };

            const fetchBridgeList = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${vm.node}/networks`);
                    if (response && response.ok) {
                        setBridgeList(await response.json());
                    }
                } catch (error) {
                    console.error('to load bridge list:', error);
                }
            };

            const fetchISOList = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${vm.node}/isos`);
                    if (response && response.ok) {
                        setIsoList(await response.json());
                    }
                } catch (error) {
                    console.error('to load ISO list:', error);
                }
            };

            const fetchSnapshots = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/snapshots`);
                    if (response && response.ok) {
                        setSnapshots(await response.json());
                    }
                } catch (error) {
                    console.error('to load snapshots:', error);
                }
            };

            // NS: Feb 2026 - Fetch efficient snapshots + capability
            const fetchEfficientSnapshots = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/efficient-snapshots?refresh=true`);
                    if (response && response.ok) {
                        setEfficientSnapshots(await response.json());
                    }
                } catch (error) {
                    console.error('Failed to load efficient snapshots:', error);
                }
            };

            const fetchEfficientInfo = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/snapshot-capability`);
                    if (response && response.ok) {
                        const data = await response.json();
                        setEfficientInfo(data.efficient_snapshot || null);
                    }
                } catch (error) {
                    // Not critical - just means efficient snapshots won't be offered
                }
            };

            const fetchReplications = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/replication?vmid=${vm.vmid}`);
                    if (response && response.ok) {
                        setReplications(await response.json());
                    }
                } catch (error) {
                    console.error('to load replications:', error);
                }
            };

            // MK: fetch cross-cluster replication jobs for this VM
            const fetchCrossClusterRepls = async () => {
                try {
                    const response = await authFetch(`${API_URL}/cross-cluster-replications?vmid=${vm.vmid}`);
                    if (response && response.ok) {
                        setCrossClusterRepls(await response.json());
                    }
                } catch (e) {
                    console.error('cross-cluster repl fetch:', e);
                }
            };

            // NS: Fetch target cluster storages/bridges when target cluster changes
            useEffect(() => {
                if (!xReplForm.target_cluster || !dashboardAuthFetch) return;
                let cancelled = false;
                const fetchTargetResources = async () => {
                    setXReplLoadingResources(true);
                    setXReplTargetStorages([]);
                    setXReplTargetBridges([]);
                    try {
                        const nodesRes = await dashboardAuthFetch(`${API_URL}/clusters/${xReplForm.target_cluster}/nodes`);
                        if (!nodesRes.ok || cancelled) return;
                        const nodesData = await nodesRes.json();
                        const onlineNode = (Array.isArray(nodesData) ? nodesData : nodesData.nodes || []).find(n => n.status === 'online');
                        if (!onlineNode || cancelled) return;
                        const nodeName = onlineNode.node || onlineNode.name;
                        const [storRes, netRes] = await Promise.all([
                            dashboardAuthFetch(`${API_URL}/clusters/${xReplForm.target_cluster}/nodes/${nodeName}/storage`),
                            dashboardAuthFetch(`${API_URL}/clusters/${xReplForm.target_cluster}/nodes/${nodeName}/networks`)
                        ]);
                        if (cancelled) return;
                        if (storRes.ok) {
                            const storData = await storRes.json();
                            const storages = (Array.isArray(storData) ? storData : storData.storages || [])
                                .filter(s => s.content && (s.content.includes('images') || s.content.includes('rootdir')));
                            setXReplTargetStorages(storages);
                        }
                        if (netRes.ok) {
                            const netData = await netRes.json();
                            const bridges = (Array.isArray(netData) ? netData : netData.networks || [])
                                .filter(n => n.type === 'bridge' || n.type === 'OVSBridge' || n.source === 'sdn');
                            setXReplTargetBridges(bridges);
                        }
                    } catch (err) {
                        console.error('Error fetching target cluster resources:', err);
                    }
                    if (!cancelled) setXReplLoadingResources(false);
                };
                fetchTargetResources();
                return () => { cancelled = true; };
            }, [xReplForm.target_cluster]);

            // NS: Fetch backups for this VM
            const fetchBackups = async () => {
                setBackupLoading(true);
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/backups`);
                    if (response && response.ok) {
                        setVmBackups(await response.json());
                    }
                } catch (error) {
                    console.error('failed to load backups:', error);
                } finally {
                    setBackupLoading(false);
                }
            };

            // MK: Fetch VM History (Proxmox Tasks + PegaProx Audit)
            const fetchHistory = async () => {
                setHistoryLoading(true);
                try {
                    // Fetch Proxmox tasks for this VM
                    const tasksRes = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${vm.node}/tasks?vmid=${vm.vmid}&limit=50`);
                    if (tasksRes && tasksRes.ok) {
                        setVmProxmoxTasks(await tasksRes.json());
                    }
                    
                    // Fetch PegaProx audit log for this VM
                    const auditRes = await authFetch(`${API_URL}/clusters/${clusterId}/audit?vmid=${vm.vmid}&limit=50`);
                    if (auditRes && auditRes.ok) {
                        setVmPegaproxActions(await auditRes.json());
                    }
                } catch (error) {
                    console.error('Failed to load history:', error);
                } finally {
                    setHistoryLoading(false);
                }
            };

            const fetchFirewallData = async () => {
                setFwLoading(true);
                try {
                    const base = `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall`;
                    const [optRes, rulesRes, aliasRes, ipsetRes, refsRes] = await Promise.all([
                        authFetch(`${base}/options`),
                        authFetch(`${base}/rules`),
                        authFetch(`${base}/aliases`),
                        authFetch(`${base}/ipset`),
                        authFetch(`${base}/refs`)
                    ]);
                    if (optRes?.ok) setFwOptions(await optRes.json());
                    if (rulesRes?.ok) setFwRules(await rulesRes.json());
                    if (aliasRes?.ok) setFwAliases(await aliasRes.json());
                    if (ipsetRes?.ok) setFwIpsets(await ipsetRes.json());
                    if (refsRes?.ok) setFwRefs(await refsRes.json());
                } catch (e) {
                    console.error('Failed to load firewall data:', e);
                }
                setFwLoading(false);
            };

            const fetchFwLog = async () => {
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/log`);
                    if (res?.ok) setFwLog(await res.json());
                } catch (e) {}
            };

            const fetchClusterNodes = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/metrics`);
                    if (response && response.ok) {
                        const metrics = await response.json();
                        const allNodes = Object.keys(metrics);
                        setAllClusterNodes(allNodes);
                        setClusterNodes(allNodes.filter(n => n !== vm.node));
                    }
                } catch (error) {
                    console.error('to load cluster nodes:', error);
                }
            };

            // Snapshot operations - NS: Feb 2026 enhanced with efficient mode
            const handleCreateSnapshot = async (snapname, description, vmstate, modeInfo) => {
                setSnapshotLoading(true);
                try {
                    if (modeInfo?.mode === 'efficient') {
                        // Create efficient (LVM COW) snapshot
                        const response = await authFetch(
                            `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/efficient-snapshots`,
                            {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ snapname, description, snap_size_gb: modeInfo.snap_size_gb })
                            }
                        );
                        if (response && response.ok) {
                            const data = await response.json();
                            const savings = data.space_savings;
                            addToast(`${t('efficientSnapshotCreated')}: '${snapname}' (${savings?.savings_percent}% ${t('spaceSavings').toLowerCase()})`);
                            setShowCreateSnapshot(false);
                            await fetchEfficientSnapshots();
                        } else if (response) {
                            const err = await response.json();
                            addToast(err.error || t('snapshotFailed'), 'error');
                        }
                    } else {
                        // Standard Proxmox snapshot
                        const response = await authFetch(
                            `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/snapshots`,
                            {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ snapname, description, vmstate })
                            }
                        );
                        if (response && response.ok) {
                            addToast(`${t('snapshotCreated') || 'Snapshot created'}: '${snapname}'`);
                            setShowCreateSnapshot(false);
                            await fetchSnapshots();
                        } else if (response) {
                            const err = await response.json();
                            addToast(err.error || t('snapshotFailed'), 'error');
                        }
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setSnapshotLoading(false);
            };

            // NS: quick confirm before delete, then refresh list
            const handleDeleteSnapshot = async (snapname) => {
                if (!confirm(`${t('confirmDelete')} '${snapname}'?`)) return;
                setSnapshotLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/snapshots/${snapname}`,
                        { method: 'DELETE' }
                    );
                    if (response?.ok) {
                        addToast(t('snapshotDeleted'));
                        await fetchSnapshots();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('deleteFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setSnapshotLoading(false);
            };

            const handleRollbackSnapshot = async (snapname) => {
                if (!confirm(`${snapname}: ${t('rollbackConfirm')}`)) return;
                setSnapshotLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/snapshots/${snapname}/rollback`,
                        { method: 'POST' }
                    );
                    if (response && response.ok) {
                        addToast(`${t('rollbackStarted') || 'Rollback started'}: '${snapname}'`);
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('rollbackFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setSnapshotLoading(false);
            };

            // NS: Feb 2026 - Efficient snapshot delete/rollback
            const handleDeleteEfficientSnapshot = async (snapId, snapname) => {
                if (!confirm(`${t('confirmDelete')} '${snapname}'?`)) return;
                setSnapshotLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/efficient-snapshots/${snapId}`,
                        { method: 'DELETE' }
                    );
                    if (response?.ok) {
                        addToast(t('efficientSnapshotDeleted'));
                        await fetchEfficientSnapshots();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('deleteFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setSnapshotLoading(false);
            };

            const handleRollbackEfficientSnapshot = async (snapId, snapname) => {
                if (!confirm(`${snapname}: ${t('rollbackConfirm')}\n\n${t('vmMustBeStopped')}`)) return;
                setSnapshotLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/efficient-snapshots/${snapId}/rollback`,
                        { method: 'POST' }
                    );
                    if (response && response.ok) {
                        addToast(t('efficientSnapshotRollback'));
                        await fetchEfficientSnapshots();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('rollbackFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setSnapshotLoading(false);
            };

            // NS: Backup operations - Dec 2025
            // finally got around to implementing this, been on the TODO list forever
            const handleCreateBackup = async (storage, mode, compress, notes) => {
                setBackupLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/backups/create`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ storage, mode, compress, notes })
                        }
                    );
                    if (response && response.ok) {
                        addToast(t('backupStarted') || 'Backup started');
                        setShowCreateBackup(false);
                        // TODO: maybe auto-refresh backup list after a delay?
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || 'Backup failed', 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setBackupLoading(false);
            };
            
            const handleRestoreBackup = async (volid, targetVmid, storage, startAfter) => {
                // LW: confirmation before restore - learned this the hard way lol
                if (!confirm(t('confirmRestore') || `Really restore this backup? ${targetVmid === vm.vmid ? 'VM will be overwritten!' : ''}`)) return;
                
                setBackupLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/backups/restore`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ volid, target_vmid: targetVmid, storage, start: startAfter })
                        }
                    );
                    if (response && response.ok) {
                        const result = await response.json();
                        addToast(t('restoreStarted') || `Restore started (VMID: ${result.vmid})`);
                        setShowRestoreBackup(null);
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || 'Restore failed', 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setBackupLoading(false);
            };
            
            const handleDeleteBackup = async (volid) => {
                if (!confirm(t('confirmDeleteBackup') || 'Really delete this backup?')) return;
                
                setBackupLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/backups/${encodeURIComponent(volid)}`,
                        { method: 'DELETE' }
                    );
                    if (response && response.ok) {
                        addToast(t('backupDeleted') || 'Backup deleted');
                        await fetchBackups();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || 'Delete failed', 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setBackupLoading(false);
            };

            // Replication operations
            const handleCreateReplication = async (target, schedule, rate, comment) => {
                setReplicationLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/replication`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ vmid: vm.vmid, target, schedule, rate, comment })
                        }
                    );
                    if (response && response.ok) {
                        addToast(t('replicationCreated'), 'success');
                        setShowCreateReplication(false);
                        await fetchReplications();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || 'Creation failed', 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
                setReplicationLoading(false);
            };

            const handleDeleteReplication = async (jobId) => {
                if (!confirm(t('confirmDeleteReplication') || `Really delete replication job '${jobId}'?`)) return;
                setReplicationLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/replication/${jobId}`,
                        { method: 'DELETE' }
                    );
                    if (response && response.ok) {
                        addToast(t('replicationDeleted'), 'success');
                        await fetchReplications();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || 'Delete failed', 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
                setReplicationLoading(false);
            };

            const handleRunReplicationNow = async (jobId) => {
                setReplicationLoading(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/replication/${jobId}/run`,
                        { method: 'POST' }
                    );
                    if (response && response.ok) {
                        addToast(t('replicationStarted'), 'success');
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('startFailed'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
                setReplicationLoading(false);
            };

            // MK: cross-cluster replication handlers
            const handleCreateXRepl = async () => {
                try {
                    const response = await authFetch(`${API_URL}/cross-cluster-replications`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            source_cluster: clusterId,
                            vmid: vm.vmid,
                            vm_type: vm.type || 'qemu',
                            ...xReplForm
                        })
                    });
                    if (response && response.ok) {
                        addToast(t('xReplCreated'), 'success');
                        setShowCreateXRepl(false);
                        setXReplForm({ target_cluster: '', target_storage: '', target_bridge: 'vmbr0', schedule: '0 */6 * * *', retention: 3 });
                        await fetchCrossClusterRepls();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('xReplCreateFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleDeleteXRepl = async (jobId) => {
                if (!confirm(t('confirmDeleteXRepl'))) return;
                try {
                    const response = await authFetch(`${API_URL}/cross-cluster-replications/${jobId}`, { method: 'DELETE' });
                    if (response && response.ok) {
                        addToast(t('xReplDeleted'), 'success');
                        await fetchCrossClusterRepls();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('xReplDeleteFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleRunXReplNow = async (jobId) => {
                try {
                    const response = await authFetch(`${API_URL}/cross-cluster-replications/${jobId}/run`, { method: 'POST' });
                    if (response && response.ok) {
                        addToast(t('xReplStarted'), 'success');
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('xReplStartFailed'), 'error');
                    }
                } catch (error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleChange = (section, key, value) => {
                setChanges(prev => ({
                    ...prev,
                    [key]: value
                }));
                setHasChanges(true);
            };

            const handleSave = async () => {
                if (Object.keys(changes).length === 0) return;
                
                setSaving(true);
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`,
                        {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(changes)
                        }
                    );
                    
                    if (response && response.ok) {
                        addToast(t('configSaved'), 'success');
                        setChanges({});
                        setHasChanges(false);
                        await fetchConfig();
                    } else {
                        const err = await response.json();
                        addToast(err.error || t('saveFailed'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
                setSaving(false);
            };

            // Disk operations - LW: refactored this like 3 times, finally happy with it
            // NS: Just don't touch the size parsing, that took forever to get right
            const handleAddDisk = async (diskConfig) => {
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/disks`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(diskConfig)
                        }
                    );
                    if (response && response.ok) {
                        addToast(t('diskAdded') || 'Disk added');
                        setShowAddDisk(false);
                        // MK: Small delay to allow Proxmox to allocate the disk
                        await new Promise(resolve => setTimeout(resolve, 500));
                        await fetchConfig();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('error'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleRemoveDisk = async (diskId) => {
                if (!confirm(`${t('removeDiskConfirm') || 'Really remove disk'} ${diskId}? ${t('dataWillBeDeleted') || 'Data will be permanently deleted!'}`)) return;
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/disks/${diskId}?delete_data=true`,
                        { method: 'DELETE' }
                    );
                    if (response && response.ok) {
                        addToast(t('diskDeleted') || 'Disk deleted');
                        await fetchConfig();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('error'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            // MK: Detach disk - removes from VM but keeps as unused
            const handleDetachDisk = async (diskId) => {
                if (!confirm(`${t('detachDiskConfirm') || 'Really detach disk?'} ${diskId}`)) return;
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/disks/${diskId}`,
                        { method: 'DELETE' }
                    );
                    if (response && response.ok) {
                        addToast(t('diskDetached') || 'Disk detached');
                        await fetchConfig();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('error'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleResizeDisk = async (diskId, newSize) => {
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/resize`,
                        {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ disk: diskId, size: newSize })
                        }
                    );
                    if (response && response.ok) {
                        addToast(t('diskResized') || 'Disk resized');
                        setShowResizeDisk(null);
                        await fetchConfig();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('error'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleMoveDisk = async (diskId, targetStorage, deleteOriginal = true) => {
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/disks/${diskId}/move`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ storage: targetStorage, delete: deleteOriginal })
                        }
                    );
                    if (response && response.ok) {
                        addToast(t('moveStarted') || 'Move started');
                        setShowMoveDisk(null);
                        await fetchConfig();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('error'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            // CD-ROM operations
            const handleMountISO = async (isoPath, drive = 'ide2') => {
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/qemu/${vm.vmid}/cdrom`,
                        {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ iso: isoPath, drive: drive })
                        }
                    );
                    if (response && response.ok) {
                        addToast(isoPath ? (t('isoMounted') || `ISO mounted on ${drive}`) : (t('isoEjected') || `${drive} ejected`));
                        setShowMountISO(false);
                        await fetchConfig();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('error'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            // Network operations
            const handleAddNetwork = async (netConfig) => {
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/networks`,
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(netConfig)
                        }
                    );
                    if (response && response.ok) {
                        addToast(t('vmNetworkAdded'));
                        setShowAddNetwork(false);
                        await fetchConfig();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('error'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleUpdateNetwork = async (netId, netConfig) => {
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/networks/${netId}`,
                        {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(netConfig)
                        }
                    );
                    if (response && response.ok) {
                        addToast(t('vmNetworkUpdated'));
                        setShowEditNetwork(null);
                        await fetchConfig();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('error'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            const handleRemoveNetwork = async (netId) => {
                if (!confirm(`${t('removeNetworkConfirm') || 'Really remove network'} ${netId}?`)) return;
                try {
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/networks/${netId}`,
                        { method: 'DELETE' }
                    );
                    if (response && response.ok) {
                        addToast(t('vmNetworkRemoved'));
                        await fetchConfig();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('error'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            // LW: Toggle network link_down state (simulates cable unplug)
            const handleToggleNetworkLink = async (netId, currentLinkDown) => {
                try {
                    const newLinkDown = !currentLinkDown;
                    const response = await authFetch(
                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/networks/${netId}/link`,
                        {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ link_down: newLinkDown })
                        }
                    );
                    if (response && response.ok) {
                        addToast(newLinkDown ? t('networkDisconnected') : t('connectNetwork'), newLinkDown ? 'warning' : 'success');
                        await fetchConfig();
                    } else if (response) {
                        const err = await response.json();
                        addToast(err.error || t('error'), 'error');
                    }
                } catch(error) {
                    addToast(t('connectionError'), 'error');
                }
            };

            // Helper functions
            const generateMAC = () => {
                const hex = '0123456789ABCDEF';
                let mac = '02';
                for (let i = 0; i < 5; i++) {
                    mac += ':' + hex[Math.floor(Math.random() * 16)] + hex[Math.floor(Math.random() * 16)];
                }
                return mac;
            };

            const getNextDiskId = (busType = 'scsi') => {
                const existing = config?.disks?.filter(d => d.id.startsWith(busType)).map(d => parseInt(d.id.replace(busType, ''))) || [];
                for (let i = 0; i < 30; i++) {
                    if (!existing.includes(i)) return `${busType}${i}`;
                }
                return `${busType}0`;
            };

            const getNextNetId = () => {
                const existing = config?.networks?.map(n => parseInt(n.id.replace('net', ''))) || [];
                for (let i = 0; i < 10; i++) {
                    if (!existing.includes(i)) return `net${i}`;
                }
                return 'net0';
            };

            const getValue = (section, key) => {
                if (key in changes) return changes[key];
                // Try parsed section first, then raw config as fallback
                const parsedValue = config?.[section]?.[key];
                if (parsedValue !== undefined && parsedValue !== '') return parsedValue;
                // Fallback to raw config
                return config?.raw?.[key] ?? '';
            };

            const tabs = isQemu
                ? [
                    { id: 'general', labelKey: 'generalTab', icon: Icons.Server },
                    { id: 'hardware', labelKey: 'hardware', icon: Icons.Cpu },
                    { id: 'disks', labelKey: 'disks', icon: Icons.HardDrive },
                    { id: 'network', labelKey: 'networkTab', icon: Icons.Network },
                    { id: 'snapshots', labelKey: 'snapshotsTab', icon: Icons.Clock },
                    { id: 'backups', labelKey: 'backupsTab', icon: Icons.Database },
                    { id: 'replication', labelKey: 'replicationTab', icon: Icons.RefreshCw },
                    { id: 'history', labelKey: 'historyTab', icon: Icons.List },
                    { id: 'firewall', labelKey: 'firewall', icon: Icons.Shield },
                    { id: 'options', labelKey: 'optionsTab', icon: Icons.Settings },
                ]
                : [
                    { id: 'general', labelKey: 'generalTab', icon: Icons.Server },
                    { id: 'resources', labelKey: 'resourcesTab', icon: Icons.Cpu },
                    { id: 'disks', labelKey: 'storageTab', icon: Icons.HardDrive },
                    { id: 'network', labelKey: 'networkTab', icon: Icons.Network },
                    { id: 'snapshots', labelKey: 'snapshotsTab', icon: Icons.Clock },
                    { id: 'backups', labelKey: 'backupsTab', icon: Icons.Database },
                    { id: 'replication', labelKey: 'replicationTab', icon: Icons.RefreshCw },
                    { id: 'history', labelKey: 'historyTab', icon: Icons.List },
                    { id: 'firewall', labelKey: 'firewall', icon: Icons.Shield },
                    { id: 'options', labelKey: 'optionsTab', icon: Icons.Settings },
                ];

            return(
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 modal-backdrop bg-black/80">
                    <div className="w-full max-w-4xl max-h-[90vh] bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl animate-scale-in overflow-hidden flex flex-col">
                        {/* Header */}
                        <div className="flex items-center justify-between px-6 py-4 border-b border-proxmox-border bg-proxmox-dark">
                            <div className="flex items-center gap-3">
                                <div className={`p-2 rounded-lg ${isQemu ? 'bg-blue-500/10' : 'bg-purple-500/10'}`}>
                                    {isQemu ? <Icons.VM /> : <Icons.Container />}
                                </div>
                                <div>
                                    <h2 className="font-semibold text-white">{vm.name || `${isQemu ? 'VM' : 'CT'} ${vm.vmid}`}</h2>
                                    <p className="text-xs text-gray-400">
                                        {isQemu ? 'QEMU Virtual Machine' : 'LXC Container'} · ID {vm.vmid} · {vm.node}
                                    </p>
                                </div>
                            </div>
                            <div className="flex items-center gap-2">
                                {hasChanges && (
                                    <span className="text-xs text-yellow-400 bg-yellow-500/10 px-2 py-1 rounded">
                                        {t('unsavedChanges') || 'Unsaved Changes'}
                                    </span>
                                )}
                                <button
                                    onClick={onClose}
                                    className="p-2 rounded-lg hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition-colors"
                                >
                                    <Icons.X />
                                </button>
                            </div>
                        </div>

                        {/* Tabs */}
                        <div className="flex items-center gap-1 px-6 py-3 border-b border-proxmox-border bg-proxmox-dark/50 overflow-x-auto">
                            {tabs.map(tab => (
                                <button
                                    key={tab.id}
                                    onClick={() => setActiveTab(tab.id)}
                                    className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
                                        activeTab === tab.id
                                            ? 'bg-proxmox-orange text-white'
                                            : 'text-gray-400 hover:text-white hover:bg-proxmox-hover'
                                    }`}
                                >
                                    <tab.icon />
                                    {t(tab.labelKey)}
                                </button>
                            ))}
                        </div>

                        {/* Content */}
                        <div className="flex-1 overflow-y-auto p-6">
                            {loading ? (
                                <div className="flex items-center justify-center h-64">
                                    <div className="animate-spin w-8 h-8 border-2 border-proxmox-orange border-t-transparent rounded-full"></div>
                                </div>
                            ) : configError ? (
                                /* MK: Show error when config fails to load */
                                <div className="flex flex-col items-center justify-center h-64 text-center">
                                    <Icons.AlertTriangle className="w-12 h-12 text-red-400 mb-4" />
                                    <p className="text-red-400 font-medium mb-2">{configError}</p>
                                    <p className="text-gray-500 text-sm mb-4">{t('checkConnectionAndRetry') || 'Please check your connection and try again.'}</p>
                                    <button 
                                        onClick={() => { setConfigError(null); fetchConfig(); }}
                                        className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600 flex items-center gap-2"
                                    >
                                        <Icons.RotateCw className="w-4 h-4" />
                                        {t('retry') || 'Retry'}
                                    </button>
                                </div>
                            ) : config ? (
                                <>
                                    {/* General Tab */}
                                    {activeTab === 'general' && (
                                        <div className="space-y-6">
                                            <div className="grid grid-cols-2 gap-4">
                                                <ConfigInputField
                                                    label={isQemu ? t('name') : t('hostname')}
                                                    value={getValue('general', isQemu ? 'name' : 'hostname')}
                                                    onChange={(v) => handleChange('general', isQemu ? 'name' : 'hostname', v)}
                                                />
                                                <ConfigInputField
                                                    label={t('tags')}
                                                    value={getValue('general', 'tags')}
                                                    onChange={(v) => handleChange('general', 'tags', v)}
                                                />
                                            </div>
                                            <div>
                                                <label className="block text-xs font-medium text-gray-400 mb-1">{t('description')}</label>
                                                <textarea
                                                    value={getValue('general', 'description')}
                                                    onChange={(e) => handleChange('general', 'description', e.target.value)}
                                                    rows={3}
                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm focus:outline-none focus:border-proxmox-orange resize-none"
                                                />
                                            </div>
                                            {config.status && (
                                                <div className="grid grid-cols-3 gap-4 p-4 bg-proxmox-dark rounded-lg">
                                                    <div>
                                                        <div className="text-xs text-gray-500">{t('status')}</div>
                                                        <div className={`font-medium ${config.status.status === 'running' ? 'text-green-400' : 'text-red-400'}`}>
                                                            {config.status.status === 'running' ? t('running') : t('stopped')}
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <div className="text-xs text-gray-500">{t('cpuUsage')}</div>
                                                        <div className="font-medium text-white">{((config.status.cpu || 0) * 100).toFixed(1)}%</div>
                                                    </div>
                                                    <div>
                                                        <div className="text-xs text-gray-500">{t('ramUsage')}</div>
                                                        <div className="font-medium text-white">
                                                            {((config.status.mem || 0) / 1073741824).toFixed(1)} GB
                                                        </div>
                                                    </div>
                                                </div>
                                            )}
                                            
                                            {/* Lock Warning and Unlock Button */}
                                            {config.lock?.locked && (
                                                <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                                    <div className="flex items-center justify-between">
                                                        <div className="flex items-center gap-2">
                                                            <Icons.AlertTriangle className="text-yellow-400" />
                                                            <div>
                                                                <div className="text-yellow-400 font-medium">{t('vmLocked')}</div>
                                                                <div className="text-xs text-yellow-300/70">{config.lock?.description || config.lock?.reason || 'Locked'}</div>
                                                            </div>
                                                        </div>
                                                        <button
                                                            onClick={async () => {
                                                                try {
                                                                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/unlock`, {
                                                                        method: 'POST'
                                                                    });
                                                                    if (response && response.ok) {
                                                                        addToast(t('vmUnlocked'), 'success');
                                                                        fetchConfig(); // Reload config
                                                                    } else {
                                                                        const err = await response.json();
                                                                        addToast(err.error || t('deleteFailed'), 'error');
                                                                    }
                                                                } catch(e) {
                                                                    addToast(t('connectionError'), 'error');
                                                                }
                                                            }}
                                                            className="px-3 py-1.5 bg-yellow-500/20 hover:bg-yellow-500/30 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm font-medium transition-colors"
                                                        >
                                                            {t('unlockVm')}
                                                        </button>
                                                    </div>
                                                    <div className="mt-2 text-xs text-gray-500">
                                                        CLI: <code className="text-green-400">{config.lock?.unlock_command}</code>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Hardware/Resources Tab */}
                                    {(activeTab === 'hardware' || activeTab === 'resources') && (
                                        <div className="space-y-6">
                                            <div className="grid grid-cols-2 gap-4">
                                                <ConfigInputField
                                                    label={t('cpuCores')}
                                                    type="number"
                                                    value={getValue('hardware', 'cores')}
                                                    onChange={(v) => handleChange('hardware', 'cores', v)}
                                                    needsRestart={vm.status === 'running'}
                                                />
                                                {isQemu && (
                                                    <ConfigInputField
                                                        label={t('sockets')}
                                                        type="number"
                                                        value={getValue('hardware', 'sockets')}
                                                        onChange={(v) => handleChange('hardware', 'sockets', v)}
                                                        needsRestart={true}
                                                    />
                                                )}
                                                {!isQemu && (
                                                    <ConfigInputField
                                                        label={t('cpuLimit')}
                                                        type="number"
                                                        value={getValue('hardware', 'cpulimit')}
                                                        onChange={(v) => handleChange('hardware', 'cpulimit', v)}
                                                        suffix={t('cores')}
                                                    />
                                                )}
                                            </div>
                                            <div className="grid grid-cols-2 gap-4">
                                                <MemoryInputField
                                                    label={t('memory')}
                                                    value={getValue('hardware', 'memory') || 2048}
                                                    onChange={(v) => handleChange('hardware', 'memory', v)}
                                                    minMB={128}
                                                    stepMB={128}
                                                    needsRestart={vm.status === 'running'}
                                                />
                                                {isQemu ? (
                                                    <MemoryInputField
                                                        label={t('ballooningMinimum')}
                                                        value={getValue('hardware', 'balloon') || 0}
                                                        onChange={(v) => handleChange('hardware', 'balloon', v)}
                                                        minMB={0}
                                                        stepMB={128}
                                                    />
                                                ) : (
                                                    <MemoryInputField
                                                        label={t('swap')}
                                                        value={getValue('hardware', 'swap') || 512}
                                                        onChange={(v) => handleChange('hardware', 'swap', v)}
                                                        minMB={0}
                                                        stepMB={64}
                                                    />
                                                )}
                                            </div>
                                            {isQemu && (
                                                <>
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <ConfigInputField
                                                            label={t('cpuType')}
                                                            value={getValue('hardware', 'cpu')}
                                                            onChange={(v) => handleChange('hardware', 'cpu', v)}
                                                            options={hardwareOptions?.cpu_types || ['host', 'kvm64', 'qemu64']}
                                                            needsRestart={true}
                                                        />
                                                        <ConfigInputField
                                                            label="VGA"
                                                            value={getValue('hardware', 'vga')}
                                                            onChange={(v) => handleChange('hardware', 'vga', v)}
                                                            options={[
                                                                { value: 'std', label: 'Standard VGA' },
                                                                { value: 'virtio', label: 'VirtIO-GPU' },
                                                                { value: 'virtio-gl', label: 'VirtIO-GPU (virgl)' },
                                                                { value: 'qxl', label: 'SPICE (QXL)' },
                                                                { value: 'vmware', label: 'VMware compatible' },
                                                                { value: 'cirrus', label: 'Cirrus Logic' },
                                                                { value: 'none', label: t('none') },
                                                            ]}
                                                            needsRestart={true}
                                                        />
                                                    </div>
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <ConfigInputField
                                                            label="BIOS"
                                                            value={getValue('hardware', 'bios')}
                                                            onChange={(v) => handleChange('hardware', 'bios', v)}
                                                            options={[
                                                                { value: 'seabios', label: 'SeaBIOS (Legacy)' },
                                                                { value: 'ovmf', label: 'OVMF (UEFI)' },
                                                            ]}
                                                            needsRestart={true}
                                                        />
                                                        <ConfigInputField
                                                            label={t('scsiController')}
                                                            value={getValue('hardware', 'scsihw')}
                                                            onChange={(v) => handleChange('hardware', 'scsihw', v)}
                                                            options={hardwareOptions?.scsi_controllers || [
                                                                { value: 'virtio-scsi-pci', label: 'VirtIO SCSI' },
                                                                { value: 'virtio-scsi-single', label: 'VirtIO SCSI Single' },
                                                                { value: 'lsi', label: 'LSI 53C895A' },
                                                            ]}
                                                            needsRestart={true}
                                                        />
                                                    </div>
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <ConfigInputField
                                                            label={t('machineType')}
                                                            value={getValue('hardware', 'machine')}
                                                            onChange={(v) => handleChange('hardware', 'machine', v)}
                                                            options={hardwareOptions?.machine_types || [
                                                                { value: '', label: t('default') },
                                                                // q35 versions
                                                                { value: 'q35', label: 'q35 (Latest)' },
                                                                { value: 'pc-q35-10.1', label: 'q35 10.1' },
                                                                { value: 'pc-q35-10.0+pve1', label: 'q35 10.0+pve1' },
                                                                { value: 'pc-q35-10.0', label: 'q35 10.0' },
                                                                { value: 'pc-q35-9.2+pve1', label: 'q35 9.2+pve1' },
                                                                { value: 'pc-q35-9.2', label: 'q35 9.2' },
                                                                { value: 'pc-q35-9.1', label: 'q35 9.1' },
                                                                { value: 'pc-q35-9.0', label: 'q35 9.0' },
                                                                { value: 'pc-q35-8.2', label: 'q35 8.2' },
                                                                { value: 'pc-q35-8.1', label: 'q35 8.1' },
                                                                { value: 'pc-q35-8.0', label: 'q35 8.0' },
                                                                { value: 'pc-q35-7.2', label: 'q35 7.2' },
                                                                { value: 'pc-q35-7.1', label: 'q35 7.1' },
                                                                { value: 'pc-q35-7.0', label: 'q35 7.0' },
                                                                { value: 'pc-q35-6.2', label: 'q35 6.2' },
                                                                { value: 'pc-q35-6.1', label: 'q35 6.1' },
                                                                { value: 'pc-q35-6.0', label: 'q35 6.0' },
                                                                { value: 'pc-q35-5.2', label: 'q35 5.2' },
                                                                { value: 'pc-q35-5.1', label: 'q35 5.1' },
                                                                { value: 'pc-q35-5.0', label: 'q35 5.0' },
                                                                { value: 'pc-q35-4.2', label: 'q35 4.2' },
                                                                { value: 'pc-q35-4.1', label: 'q35 4.1' },
                                                                { value: 'pc-q35-4.0', label: 'q35 4.0' },
                                                                { value: 'pc-q35-3.1', label: 'q35 3.1' },
                                                                { value: 'pc-q35-3.0', label: 'q35 3.0' },
                                                                { value: 'pc-q35-2.12', label: 'q35 2.12' },
                                                                { value: 'pc-q35-2.11', label: 'q35 2.11' },
                                                                { value: 'pc-q35-2.10', label: 'q35 2.10' },
                                                                // i440fx versions
                                                                { value: 'i440fx', label: 'i440fx (Latest)' },
                                                                { value: 'pc-i440fx-10.1', label: 'i440fx 10.1' },
                                                                { value: 'pc-i440fx-10.0+pve1', label: 'i440fx 10.0+pve1' },
                                                                { value: 'pc-i440fx-10.0', label: 'i440fx 10.0' },
                                                                { value: 'pc-i440fx-9.2+pve1', label: 'i440fx 9.2+pve1' },
                                                                { value: 'pc-i440fx-9.2', label: 'i440fx 9.2' },
                                                                { value: 'pc-i440fx-9.1', label: 'i440fx 9.1' },
                                                                { value: 'pc-i440fx-9.0', label: 'i440fx 9.0' },
                                                                { value: 'pc-i440fx-8.2', label: 'i440fx 8.2' },
                                                                { value: 'pc-i440fx-8.1', label: 'i440fx 8.1' },
                                                                { value: 'pc-i440fx-8.0', label: 'i440fx 8.0' },
                                                                { value: 'pc-i440fx-7.2', label: 'i440fx 7.2' },
                                                                { value: 'pc-i440fx-7.1', label: 'i440fx 7.1' },
                                                                { value: 'pc-i440fx-7.0', label: 'i440fx 7.0' },
                                                                { value: 'pc-i440fx-6.2', label: 'i440fx 6.2' },
                                                                { value: 'pc-i440fx-6.1', label: 'i440fx 6.1' },
                                                                { value: 'pc-i440fx-6.0', label: 'i440fx 6.0' },
                                                                { value: 'pc-i440fx-5.2', label: 'i440fx 5.2' },
                                                                { value: 'pc-i440fx-5.1', label: 'i440fx 5.1' },
                                                                { value: 'pc-i440fx-5.0', label: 'i440fx 5.0' },
                                                                { value: 'pc-i440fx-4.2', label: 'i440fx 4.2' },
                                                                { value: 'pc-i440fx-4.1', label: 'i440fx 4.1' },
                                                                { value: 'pc-i440fx-4.0', label: 'i440fx 4.0' },
                                                                { value: 'pc-i440fx-3.1', label: 'i440fx 3.1' },
                                                                { value: 'pc-i440fx-3.0', label: 'i440fx 3.0' },
                                                                { value: 'pc-i440fx-2.12', label: 'i440fx 2.12' },
                                                                { value: 'pc-i440fx-2.11', label: 'i440fx 2.11' },
                                                                { value: 'pc-i440fx-2.10', label: 'i440fx 2.10' },
                                                            ]}
                                                            needsRestart={true}
                                                        />
                                                        {/* LW: vIOMMU for nested virt and GPU passthrough
                                                            MK: Appends to machine string like "q35,viommu=intel" */}
                                                        <ConfigInputField
                                                            label="vIOMMU"
                                                            value={getValue('hardware', 'machine')?.includes('viommu=') ? getValue('hardware', 'machine').split('viommu=')[1]?.split(',')[0] : ''}
                                                            onChange={(v) => {
                                                                const currentMachine = getValue('hardware', 'machine') || '';
                                                                const baseMachine = currentMachine.split(',')[0];
                                                                if (v && v !== 'none') {
                                                                    handleChange('hardware', 'machine', `${baseMachine},viommu=${v}`);
                                                                } else {
                                                                    handleChange('hardware', 'machine', baseMachine);
                                                                }
                                                            }}
                                                            options={[
                                                                { value: '', label: t('default') + ' (None)' },
                                                                { value: 'intel', label: 'Intel (VT-d)' },
                                                                { value: 'virtio', label: 'VirtIO' },
                                                            ]}
                                                            needsRestart={true}
                                                        />
                                                    </div>
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div className="flex items-center gap-4 pt-2">
                                                            <ConfigCheckboxField
                                                                label={t('enableNuma')}
                                                                checked={getValue('hardware', 'numa') == 1}
                                                                onChange={(v) => handleChange('hardware', 'numa', v)}
                                                                needsRestart={true}
                                                                t={t}
                                                            />
                                                        </div>
                                                        <div></div>
                                                    </div>
                                                    
                                                    {/* EFI Disk & TPM Section - MK: For UEFI and Windows 11 */}
                                                    {getValue('hardware', 'bios') === 'ovmf' && (
                                                        <div className="mt-6 pt-6 border-t border-proxmox-border">
                                                            <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                                                                🔐 {t('efiTpmSettings') || 'EFI & TPM Settings'}
                                                                {vm.status === 'running' && (
                                                                    <span className="text-xs text-yellow-400 bg-yellow-500/10 px-2 py-0.5 rounded">
                                                                        {t('changesAfterRestart')}
                                                                    </span>
                                                                )}
                                                            </h3>
                                                            
                                                            {/* EFI Disk */}
                                                            <div className="mb-4">
                                                                <div className="flex justify-between items-center mb-2">
                                                                    <span className="text-sm text-gray-400">{t('efiDisk') || 'EFI Disk'}</span>
                                                                </div>
                                                                {config?.raw?.efidisk0 ? (
                                                                    <div className="p-3 bg-proxmox-dark rounded-lg">
                                                                        <div className="flex items-center justify-between">
                                                                            <div className="flex items-center gap-2">
                                                                                <Icons.HardDrive className="w-4 h-4 text-blue-400" />
                                                                                <span className="text-sm font-mono text-gray-300">{config.raw.efidisk0}</span>
                                                                            </div>
                                                                            <div className="flex items-center gap-2">
                                                                                <span className="text-xs text-green-400 bg-green-500/10 px-2 py-0.5 rounded">{t('configured') || 'Configured'}</span>
                                                                                <button
                                                                                    onClick={async () => {
                                                                                        if (!confirm(t('confirmDeleteEfiDisk') || 'Delete EFI disk? This may prevent the VM from booting.')) return;
                                                                                        try {
                                                                                            const res = await fetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`, {
                                                                                                method: 'PUT',
                                                                                                credentials: 'include',
                                                                                                headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                                                                                body: JSON.stringify({ delete: 'efidisk0' })
                                                                                            });
                                                                                            if (res.ok) {
                                                                                                addToast(t('efiDiskDeleted') || 'EFI disk deleted', 'success');
                                                                                                fetchConfig();
                                                                                            } else {
                                                                                                const err = await res.json();
                                                                                                addToast(err.error || 'Error deleting EFI disk', 'error');
                                                                                            }
                                                                                        } catch (e) {
                                                                                            addToast('Error deleting EFI disk', 'error');
                                                                                        }
                                                                                    }}
                                                                                    className="text-xs px-2 py-1 text-red-400 hover:bg-red-500/20 rounded"
                                                                                    title={t('delete')}
                                                                                >
                                                                                    <Icons.Trash className="w-3.5 h-3.5" />
                                                                                </button>
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                ) : (
                                                                    <div className="p-3 bg-proxmox-dark rounded-lg border border-dashed border-proxmox-border">
                                                                        <div className="flex items-center justify-between">
                                                                            <span className="text-sm text-gray-500">{t('noEfiDisk') || 'No EFI disk configured'}</span>
                                                                            <button
                                                                                onClick={() => setShowAddEfiDisk(true)}
                                                                                className="text-xs px-3 py-1.5 bg-blue-500/20 text-blue-400 rounded hover:bg-blue-500/30 flex items-center gap-1"
                                                                            >
                                                                                <Icons.Plus className="w-3 h-3" />
                                                                                {t('addEfiDisk') || 'Add EFI Disk'}
                                                                            </button>
                                                                        </div>
                                                                        <p className="text-xs text-gray-600 mt-2">{t('efiDiskRequired') || 'Required for UEFI boot. Will be created automatically on first boot if not configured.'}</p>
                                                                    </div>
                                                                )}
                                                            </div>
                                                            
                                                            {/* TPM */}
                                                            <div>
                                                                <div className="flex justify-between items-center mb-2">
                                                                    <span className="text-sm text-gray-400">{t('tpmChip') || 'TPM Chip'}</span>
                                                                </div>
                                                                {config?.raw?.tpmstate0 ? (
                                                                    <div className="p-3 bg-proxmox-dark rounded-lg">
                                                                        <div className="flex items-center justify-between">
                                                                            <div className="flex items-center gap-2">
                                                                                <Icons.Shield className="w-4 h-4 text-green-400" />
                                                                                <span className="text-sm font-mono text-gray-300">{config.raw.tpmstate0}</span>
                                                                            </div>
                                                                            <div className="flex items-center gap-2">
                                                                                <span className="text-xs text-green-400 bg-green-500/10 px-2 py-0.5 rounded">TPM 2.0</span>
                                                                                <button
                                                                                    onClick={async () => {
                                                                                        if (!confirm(t('confirmDeleteTpm') || 'Delete TPM? Windows 11 and BitLocker will stop working.')) return;
                                                                                        try {
                                                                                            const res = await fetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`, {
                                                                                                method: 'PUT',
                                                                                                credentials: 'include',
                                                                                                headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                                                                                body: JSON.stringify({ delete: 'tpmstate0' })
                                                                                            });
                                                                                            if (res.ok) {
                                                                                                addToast(t('tpmDeleted') || 'TPM deleted', 'success');
                                                                                                fetchConfig();
                                                                                            } else {
                                                                                                const err = await res.json();
                                                                                                addToast(err.error || 'Error deleting TPM', 'error');
                                                                                            }
                                                                                        } catch (e) {
                                                                                            addToast('Error deleting TPM', 'error');
                                                                                        }
                                                                                    }}
                                                                                    className="text-xs px-2 py-1 text-red-400 hover:bg-red-500/20 rounded"
                                                                                    title={t('delete')}
                                                                                >
                                                                                    <Icons.Trash className="w-3.5 h-3.5" />
                                                                                </button>
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                ) : (
                                                                    <div className="p-3 bg-proxmox-dark rounded-lg border border-dashed border-proxmox-border">
                                                                        <div className="flex items-center justify-between">
                                                                            <span className="text-sm text-gray-500">{t('noTpm') || 'No TPM configured'}</span>
                                                                            <button
                                                                                onClick={() => setShowAddTpm(true)}
                                                                                className="text-xs px-3 py-1.5 bg-green-500/20 text-green-400 rounded hover:bg-green-500/30 flex items-center gap-1"
                                                                            >
                                                                                <Icons.Plus className="w-3 h-3" />
                                                                                {t('addTpm') || 'Add TPM'}
                                                                            </button>
                                                                        </div>
                                                                        <p className="text-xs text-yellow-500 mt-2 flex items-center gap-1">
                                                                            <Icons.AlertTriangle className="w-3 h-3" />
                                                                            {t('win11NeedsTpm') || 'Windows 11 requires TPM 2.0'}
                                                                        </p>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    )}
                                                    
                                                    {/* PCI/USB/Serial Passthrough Section */}
                                                    <div className="mt-6 pt-6 border-t border-proxmox-border">
                                                        <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                                                            🔌 {t('devicePassthrough')}
                                                            {vm.status === 'running' && (
                                                                <span className="text-xs text-yellow-400 bg-yellow-500/10 px-2 py-0.5 rounded">
                                                                    {t('changesAfterRestart')}
                                                                </span>
                                                            )}
                                                        </h3>
                                                        
                                                        {/* PCI Devices */}
                                                        <div className="mb-4">
                                                            <div className="flex justify-between items-center mb-2">
                                                                <span className="text-sm text-gray-400">{t('pciDevices')}</span>
                                                                <button
                                                                    onClick={() => setShowAddPci(true)}
                                                                    className="text-xs px-2 py-1 bg-proxmox-orange/20 text-proxmox-orange rounded hover:bg-proxmox-orange/30"
                                                                >
                                                                    + {t('addPci')}
                                                                </button>
                                                            </div>
                                                            {passthrough.pci?.length > 0 ? (
                                                                <div className="space-y-1">
                                                                    {passthrough.pci.map((dev, idx) => (
                                                                        <div key={idx} className="flex items-center justify-between p-2 bg-proxmox-dark rounded text-sm">
                                                                            <span className="font-mono text-gray-300">{dev.key}: {dev.value}</span>
                                                                            <button
                                                                                onClick={() => handleRemovePassthrough('pci', dev.key)}
                                                                                className="text-red-400 hover:text-red-300 p-1"
                                                                            >
                                                                                <Icons.Trash className="w-3 h-3" />
                                                                            </button>
                                                                        </div>
                                                                    ))}
                                                                </div>
                                                            ) : (
                                                                <div className="text-xs text-gray-500 italic">{t('noPciDevices')}</div>
                                                            )}
                                                        </div>
                                                        
                                                        {/* USB Devices */}
                                                        <div className="mb-4">
                                                            <div className="flex justify-between items-center mb-2">
                                                                <span className="text-sm text-gray-400">{t('usbDevices')}</span>
                                                                <button
                                                                    onClick={() => setShowAddUsb(true)}
                                                                    className="text-xs px-2 py-1 bg-proxmox-orange/20 text-proxmox-orange rounded hover:bg-proxmox-orange/30"
                                                                >
                                                                    + {t('addUsb')}
                                                                </button>
                                                            </div>
                                                            {passthrough.usb?.length > 0 ? (
                                                                <div className="space-y-1">
                                                                    {passthrough.usb.map((dev, idx) => (
                                                                        <div key={idx} className="flex items-center justify-between p-2 bg-proxmox-dark rounded text-sm">
                                                                            <span className="font-mono text-gray-300">{dev.key}: {dev.value}</span>
                                                                            <button
                                                                                onClick={() => handleRemovePassthrough('usb', dev.key)}
                                                                                className="text-red-400 hover:text-red-300 p-1"
                                                                            >
                                                                                <Icons.Trash className="w-3 h-3" />
                                                                            </button>
                                                                        </div>
                                                                    ))}
                                                                </div>
                                                            ) : (
                                                                <div className="text-xs text-gray-500 italic">{t('noUsbDevices')}</div>
                                                            )}
                                                        </div>
                                                        
                                                        {/* Serial Ports */}
                                                        <div>
                                                            <div className="flex justify-between items-center mb-2">
                                                                <span className="text-sm text-gray-400">{t('serialPorts')}</span>
                                                                <button
                                                                    onClick={() => setShowAddSerial(true)}
                                                                    className="text-xs px-2 py-1 bg-proxmox-orange/20 text-proxmox-orange rounded hover:bg-proxmox-orange/30"
                                                                >
                                                                    + {t('addSerial')}
                                                                </button>
                                                            </div>
                                                            {passthrough.serial?.length > 0 ? (
                                                                <div className="space-y-1">
                                                                    {passthrough.serial.map((dev, idx) => (
                                                                        <div key={idx} className="flex items-center justify-between p-2 bg-proxmox-dark rounded text-sm">
                                                                            <span className="font-mono text-gray-300">{dev.key}: {dev.value}</span>
                                                                            <button
                                                                                onClick={() => handleRemovePassthrough('serial', dev.key)}
                                                                                className="text-red-400 hover:text-red-300 p-1"
                                                                            >
                                                                                <Icons.Trash className="w-3 h-3" />
                                                                            </button>
                                                                        </div>
                                                                    ))}
                                                                </div>
                                                            ) : (
                                                                <div className="text-xs text-gray-500 italic">{t('noSerialPorts')}</div>
                                                            )}
                                                        </div>
                                                    </div>
                                                </>
                                            )}
                                        </div>
                                    )}

                                    {/* Disks Tab */}
                                    {activeTab === 'disks' && (
                                        <div className="space-y-4">
                                            <div className="flex justify-between items-center">
                                                <h3 className="font-medium text-white">{t('disks')}</h3>
                                                <div className="flex gap-2">
                                                    {isQemu && (
                                                        <button
                                                            onClick={() => setShowMountISO(true)}
                                                            className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm text-gray-300 hover:text-white hover:border-proxmox-orange transition-colors"
                                                        >
                                                            <Icons.Play />
                                                            {t('mountIso')}
                                                        </button>
                                                    )}
                                                    <button
                                                        onClick={() => setShowAddDisk(true)}
                                                        className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange rounded-lg text-sm text-white hover:bg-orange-600 transition-colors"
                                                    >
                                                        <Icons.Plus />
                                                        {t('addDisk')}
                                                    </button>
                                                    {isQemu && (
                                                        <button
                                                            onClick={() => setShowImportDisk(true)}
                                                            className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm text-gray-300 hover:text-white hover:border-proxmox-orange transition-colors"
                                                        >
                                                            <Icons.Download />
                                                            {t('importDisk') || 'Import Disk'}
                                                        </button>
                                                    )}
                                                </div>
                                            </div>
                                            
                                            {config.disks?.length > 0 ? (
                                                config.disks.map((disk) => (
                                                    <div key={disk.id} className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                        <div className="flex items-center justify-between mb-3">
                                                            <div className="flex items-center gap-3">
                                                                <Icons.HardDrive />
                                                                <span className="font-medium text-white">{disk.id}</span>
                                                                <span className="text-xs text-gray-500 bg-proxmox-card px-2 py-0.5 rounded">{disk.storage}</span>
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                <span className="text-sm text-proxmox-orange font-mono mr-2">{disk.size}</span>
                                                                {/* MK: Edit disk bus type */}
                                                                {isQemu && disk.id !== 'rootfs' && !disk.id.includes('efidisk') && !disk.id.includes('tpmstate') && (
                                                                    <button
                                                                        onClick={() => setShowEditDisk(disk)}
                                                                        className="p-1.5 rounded hover:bg-proxmox-hover text-gray-400 hover:text-yellow-400 transition-colors"
                                                                        title={t('editDiskType') || 'Change Bus Type'}
                                                                    >
                                                                        <Icons.Edit />
                                                                    </button>
                                                                )}
                                                                <button
                                                                    onClick={() => setShowResizeDisk(disk)}
                                                                    className="p-1.5 rounded hover:bg-proxmox-hover text-gray-400 hover:text-green-400 transition-colors"
                                                                    title={t('resize')}
                                                                >
                                                                    <Icons.Plus />
                                                                </button>
                                                                <button
                                                                    onClick={() => setShowMoveDisk(disk)}
                                                                    className="p-1.5 rounded hover:bg-proxmox-hover text-gray-400 hover:text-blue-400 transition-colors"
                                                                    title={t('move')}
                                                                >
                                                                    <Icons.ArrowRight />
                                                                </button>
                                                                {disk.id !== 'rootfs' && !disk.id.includes('efidisk') && !disk.id.includes('tpmstate') && (
                                                                    <>
                                                                        {/* MK: Only show reassign for real disks, not CD-ROM/ISO */}
                                                                        {isQemu && !disk.volume?.includes('iso') && !disk.media?.includes('cdrom') && !String(disk.value || '').includes('media=cdrom') && (
                                                                            <button
                                                                                onClick={() => setShowReassignOwner(disk)}
                                                                                className="p-1.5 rounded hover:bg-proxmox-hover text-gray-400 hover:text-purple-400 transition-colors"
                                                                                title={t('reassignOwner') || 'Reassign Owner'}
                                                                            >
                                                                                <Icons.Users />
                                                                            </button>
                                                                        )}
                                                                        <button
                                                                            onClick={() => handleDetachDisk(disk.id)}
                                                                            className="p-1.5 rounded hover:bg-proxmox-hover text-gray-400 hover:text-yellow-400 transition-colors"
                                                                            title={t('detachDisk') || 'Detach'}
                                                                        >
                                                                            <Icons.Unplug />
                                                                        </button>
                                                                        <button
                                                                            onClick={() => handleRemoveDisk(disk.id)}
                                                                            className="p-1.5 rounded hover:bg-proxmox-hover text-gray-400 hover:text-red-400 transition-colors"
                                                                            title={t('remove')}
                                                                        >
                                                                            <Icons.Trash />
                                                                        </button>
                                                                    </>
                                                                )}
                                                            </div>
                                                        </div>
                                                        <div className="grid grid-cols-4 gap-4 text-sm">
                                                            <div>
                                                                <span className="text-gray-500">Volume:</span>
                                                                <span className="ml-2 text-gray-300 font-mono text-xs">{disk.volume}</span>
                                                            </div>
                                                            {disk.cache && (
                                                                <div>
                                                                    <span className="text-gray-500">Cache:</span>
                                                                    <span className="ml-2 text-gray-300">{disk.cache}</span>
                                                                </div>
                                                            )}
                                                            {disk.iothread ? (
                                                                <div><span className="text-green-400">IOthread</span></div>
                                                            ) : null}
                                                            {disk.ssd ? (
                                                                <div><span className="text-blue-400">SSD</span></div>
                                                            ) : null}
                                                            {disk.mountpoint && (
                                                                <div>
                                                                    <span className="text-gray-500">Mount:</span>
                                                                    <span className="ml-2 text-gray-300">{disk.mountpoint}</span>
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>
                                                ))
                                            ) : (
                                                <div className="text-center py-8 text-gray-500">
                                                    {t('noDisksConfigured')}
                                                </div>
                                            )}
                                            
                                            {/* MK: Unused Disks Section - detached disks that can be reattached or deleted */}
                                            {config.unused_disks?.length > 0 && (
                                                <div className="mt-6 pt-4 border-t border-proxmox-border">
                                                    <div className="flex items-center gap-2 mb-3">
                                                        <Icons.AlertTriangle className="w-4 h-4 text-yellow-500" />
                                                        <h4 className="font-medium text-yellow-400">{t('unusedDisks') || 'Unused Disks'}</h4>
                                                        <span className="text-xs text-gray-500">({config.unused_disks.length})</span>
                                                    </div>
                                                    <p className="text-xs text-gray-500 mb-3">
                                                        {t('unusedDisksDesc') || 'These disks are detached but still exist. You can reattach or delete them.'}
                                                    </p>
                                                    {config.unused_disks.map((disk) => (
                                                        <div key={disk.id} className="p-3 bg-yellow-500/5 rounded-lg border border-yellow-500/30 mb-2">
                                                            <div className="flex items-center justify-between">
                                                                <div className="flex items-center gap-3">
                                                                    <Icons.HardDrive className="text-yellow-500" />
                                                                    <span className="font-medium text-yellow-400">{disk.id}</span>
                                                                    <span className="text-xs text-gray-400 font-mono">{disk.value}</span>
                                                                </div>
                                                                <div className="flex items-center gap-2">
                                                                    {/* MK: Open reattach modal */}
                                                                    <button
                                                                        onClick={() => setShowReattachDisk(disk)}
                                                                        className="px-2 py-1 text-xs bg-green-600/20 text-green-400 rounded hover:bg-green-600/30 transition-colors"
                                                                        title={t('reattachDisk') || 'Reattach disk'}
                                                                    >
                                                                        {t('reattach') || 'Reattach'}
                                                                    </button>
                                                                    {/* MK: Delete permanently */}
                                                                    <button
                                                                        onClick={async () => {
                                                                            if (!confirm(t('deleteUnusedDiskConfirm') || `Permanently delete ${disk.id}? This cannot be undone!`)) return;
                                                                            try {
                                                                                // First delete the unused reference, then purge the actual volume
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`, {
                                                                                    method: 'PUT',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify({ delete: disk.id })
                                                                                });
                                                                                if (res && res.ok) {
                                                                                    addToast(t('unusedDiskDeleted') || 'Unused disk deleted', 'success');
                                                                                    fetchConfig();
                                                                                } else {
                                                                                    const err = await res.json();
                                                                                    addToast(err.error || 'Error deleting disk', 'error');
                                                                                }
                                                                            } catch (e) {
                                                                                addToast('Error deleting disk', 'error');
                                                                            }
                                                                        }}
                                                                        className="px-2 py-1 text-xs bg-red-600/20 text-red-400 rounded hover:bg-red-600/30 transition-colors"
                                                                        title={t('deletePermanently') || 'Delete permanently'}
                                                                    >
                                                                        {t('delete')}
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Network Tab */}
                                    {activeTab === 'network' && (
                                        <div className="space-y-4">
                                            <div className="flex justify-between items-center">
                                                <h3 className="font-medium text-white">{t('networkInterfaces')}</h3>
                                                <button
                                                    onClick={() => setShowAddNetwork(true)}
                                                    className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange rounded-lg text-sm text-white hover:bg-orange-600 transition-colors"
                                                >
                                                    <Icons.Plus />
                                                    {t('addNetwork')}
                                                </button>
                                            </div>
                                            
                                            {config.networks?.length > 0 ? (
                                                config.networks.map((net) => (
                                                    <div key={net.id} className={`p-4 bg-proxmox-dark rounded-lg border ${net.link_down ? 'border-red-500/50' : 'border-proxmox-border'}`}>
                                                        <div className="flex items-center justify-between mb-3">
                                                            <div className="flex items-center gap-3">
                                                                <Icons.Network className={net.link_down ? 'text-red-400' : ''} />
                                                                <span className="font-medium text-white">{net.id}</span>
                                                                {net.bridge && (() => {
                                                                    const bridgeInfo = bridgeList.find(b => b.iface === net.bridge);
                                                                    const isSDN = bridgeInfo?.source === 'sdn';
                                                                    // Check if it looks like an SDN VNet name (no vmbr prefix)
                                                                    const looksLikeSDN = !bridgeInfo && net.bridge && !net.bridge.startsWith('vmbr');
                                                                    return (
                                                                        <span className={`text-xs px-2 py-0.5 rounded ${isSDN ? 'text-purple-400 bg-purple-500/10' : looksLikeSDN ? 'text-purple-400 bg-purple-500/10' : 'text-gray-500 bg-proxmox-card'}`} 
                                                                            title={bridgeInfo?.comments || (isSDN ? `SDN Zone: ${bridgeInfo?.zone}` : (looksLikeSDN ? 'Possible SDN VNet' : ''))}>
                                                                            {(isSDN || looksLikeSDN) && <span className="mr-1">🌐</span>}
                                                                            {net.bridge}
                                                                            {bridgeInfo?.zone ? ` (${bridgeInfo.zone})` : (bridgeInfo?.comments ? ` (${bridgeInfo.comments})` : '')}
                                                                            {looksLikeSDN && !bridgeInfo && ' (SDN?)'}
                                                                        </span>
                                                                    );
                                                                })()}
                                                                {/* LW: Show disconnected status */}
                                                                {net.link_down && (
                                                                    <span className="text-xs text-red-400 bg-red-500/10 px-2 py-0.5 rounded flex items-center gap-1">
                                                                        <Icons.WifiOff className="w-3 h-3" />
                                                                        {t('networkDisconnected')}
                                                                    </span>
                                                                )}
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                {net.firewall ? (
                                                                    <span className="text-xs text-green-400 bg-green-500/10 px-2 py-0.5 rounded">Firewall</span>
                                                                ) : null}
                                                                {/* NS: Connect/Disconnect toggle (QEMU only - hot-pluggable) */}
                                                                {isQemu && (
                                                                    <button
                                                                        onClick={() => handleToggleNetworkLink(net.id, net.link_down)}
                                                                        className={`p-1.5 rounded hover:bg-proxmox-hover transition-colors ${net.link_down ? 'text-red-400 hover:text-green-400' : 'text-gray-400 hover:text-red-400'}`}
                                                                        title={net.link_down ? t('connectNetwork') : t('disconnectNetwork')}
                                                                    >
                                                                        {net.link_down ? <Icons.Plug /> : <Icons.Unplug />}
                                                                    </button>
                                                                )}
                                                                <button
                                                                    onClick={() => setShowEditNetwork(net)}
                                                                    className="p-1.5 rounded hover:bg-proxmox-hover text-gray-400 hover:text-blue-400 transition-colors"
                                                                    title={t('edit')}
                                                                >
                                                                    <Icons.Cog />
                                                                </button>
                                                                <button
                                                                    onClick={() => handleRemoveNetwork(net.id)}
                                                                    className="p-1.5 rounded hover:bg-proxmox-hover text-gray-400 hover:text-red-400 transition-colors"
                                                                    title={t('remove')}
                                                                >
                                                                    <Icons.Trash />
                                                                </button>
                                                            </div>
                                                        </div>
                                                        <div className="grid grid-cols-3 gap-4 text-sm">
                                                            {isQemu ? (
                                                                <>
                                                                    <div><span className="text-gray-500">Model:</span><span className="ml-2 text-gray-300">{net.model || 'virtio'}</span></div>
                                                                    <div><span className="text-gray-500">MAC:</span><span className="ml-2 text-gray-300 font-mono text-xs">{net.macaddr || 'auto'}</span></div>
                                                                    {net.queues && <div><span className="text-gray-500">Queues:</span><span className="ml-2 text-gray-300">{net.queues}</span></div>}
                                                                </>
                                                            ) : (
                                                                <>
                                                                    <div><span className="text-gray-500">{t('name')}:</span><span className="ml-2 text-gray-300">{net.name || 'eth0'}</span></div>
                                                                    <div><span className="text-gray-500">IP:</span><span className="ml-2 text-gray-300 font-mono">{net.ip || 'dhcp'}</span></div>
                                                                    {net.gw && <div><span className="text-gray-500">Gateway:</span><span className="ml-2 text-gray-300 font-mono">{net.gw}</span></div>}
                                                                </>
                                                            )}
                                                            {net.tag && <div><span className="text-gray-500">VLAN:</span><span className="ml-2 text-gray-300">{net.tag}</span></div>}
                                                            {net.rate && <div><span className="text-gray-500">Rate:</span><span className="ml-2 text-gray-300">{net.rate} MB/s</span></div>}
                                                            {net.mtu && <div><span className="text-gray-500">MTU:</span><span className="ml-2 text-gray-300">{net.mtu}</span></div>}
                                                        </div>
                                                    </div>
                                                ))
                                            ) : (
                                                <div className="text-center py-8 text-gray-500">
                                                    {t('noNetworksConfigured')}
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Snapshots Tab */}
                                    {activeTab === 'snapshots' && (
                                        <div className="space-y-6">
                                            <div className="flex items-center justify-between">
                                                <h3 className="text-sm font-semibold text-gray-300">Snapshots</h3>
                                                <button
                                                    onClick={() => setShowCreateSnapshot(true)}
                                                    className="flex items-center gap-2 px-3 py-1.5 bg-green-600 rounded-lg text-white text-sm hover:bg-green-700"
                                                >
                                                    <Icons.Plus />
                                                    {t('createSnapshot')}
                                                </button>
                                            </div>
                                            
                                            {snapshots.length > 0 ? (
                                                <div className="space-y-3">
                                                    {snapshots.map(snap => (
                                                        <div key={snap.name} className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                            <div className="flex items-center justify-between">
                                                                <div className="flex items-center gap-3">
                                                                    <div className="p-2 bg-blue-500/10 rounded-lg">
                                                                        <Icons.Clock />
                                                                    </div>
                                                                    <div>
                                                                        <div className="font-medium text-white">{snap.name}</div>
                                                                        <div className="text-xs text-gray-400">
                                                                            {snap.snaptime ? new Date(snap.snaptime * 1000).toLocaleString() : t('unknown')}
                                                                            {snap.vmstate && <span className="ml-2 text-blue-400">+ RAM</span>}
                                                                        </div>
                                                                        {snap.description && (
                                                                            <div className="text-sm text-gray-500 mt-1">{snap.description}</div>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                                <div className="flex items-center gap-2">
                                                                    <button
                                                                        onClick={() => handleRollbackSnapshot(snap.name)}
                                                                        disabled={snapshotLoading}
                                                                        className="p-2 rounded-lg bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-400 transition-colors disabled:opacity-50"
                                                                        title={t('rollback')}
                                                                    >
                                                                        <Icons.RotateCcw />
                                                                    </button>
                                                                    <button
                                                                        onClick={() => handleDeleteSnapshot(snap.name)}
                                                                        disabled={snapshotLoading}
                                                                        className="p-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition-colors disabled:opacity-50"
                                                                        title={t('delete')}
                                                                    >
                                                                        <Icons.Trash />
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            ) : (
                                                <div className="text-center py-8 text-gray-500">
                                                    <Icons.Clock />
                                                    <p className="mt-2">{t('noSnapshots')}</p>
                                                </div>
                                            )}

                                            {/* NS: Feb 2026 - Space-Efficient Snapshots Section */}
                                            {efficientSnapshots.length > 0 && (
                                                <div className="mt-6">
                                                    <div className="flex items-center gap-2 mb-3">
                                                        <Icons.Zap className="text-green-400" />
                                                        <h3 className="text-sm font-semibold text-green-400">{t('spaceEfficientSnapshots')}</h3>
                                                        <span className="text-xs text-gray-500">({t('managedByPegaprox')})</span>
                                                    </div>
                                                    <div className="space-y-3">
                                                        {efficientSnapshots.map(snap => {
                                                            const isInvalidated = snap.status === 'invalidated';
                                                            return (
                                                                <div key={snap.id} className={`p-4 rounded-lg border ${
                                                                    isInvalidated
                                                                        ? 'bg-gray-800/50 border-gray-700'
                                                                        : 'bg-proxmox-dark border-green-500/30'
                                                                }`}>
                                                                    <div className="flex items-center justify-between mb-2">
                                                                        <div className="flex items-center gap-3">
                                                                            <div className={`p-2 rounded-lg ${isInvalidated ? 'bg-gray-500/10' : 'bg-green-500/10'}`}>
                                                                                <Icons.Zap className={isInvalidated ? 'text-gray-500' : ''} />
                                                                            </div>
                                                                            <div>
                                                                                <div className="flex items-center gap-2">
                                                                                    <span className={`font-medium ${isInvalidated ? 'text-gray-500 line-through' : 'text-white'}`}>{snap.snapname}</span>
                                                                                    <span className="px-1.5 py-0.5 text-xs rounded bg-green-500/20 text-green-400">{t('cowSnapshot')}</span>
                                                                                    {snap.fs_frozen && <span className="px-1.5 py-0.5 text-xs rounded bg-blue-500/20 text-blue-400">{t('fsFrozen')}</span>}
                                                                                </div>
                                                                                <div className="text-xs text-gray-400 mt-0.5">
                                                                                    {snap.created_at ? new Date(snap.created_at).toLocaleString() : ''}
                                                                                    <span className="ml-2 text-gray-500">
                                                                                        {snap.total_snap_alloc_gb?.toFixed(1)} GB / {snap.total_disk_size_gb?.toFixed(1)} GB
                                                                                    </span>
                                                                                </div>
                                                                                {snap.description && <div className="text-sm text-gray-500 mt-1">{snap.description}</div>}
                                                                                {isInvalidated && <div className="text-xs text-red-400 mt-1">{t('snapshotInvalidated')}</div>}
                                                                            </div>
                                                                        </div>
                                                                        {!isInvalidated && (
                                                                            <div className="flex items-center gap-2">
                                                                                <button
                                                                                    onClick={() => handleRollbackEfficientSnapshot(snap.id, snap.snapname)}
                                                                                    disabled={snapshotLoading}
                                                                                    className="p-2 rounded-lg bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-400 transition-colors disabled:opacity-50"
                                                                                    title={t('rollback')}
                                                                                >
                                                                                    <Icons.RotateCcw />
                                                                                </button>
                                                                                <button
                                                                                    onClick={() => handleDeleteEfficientSnapshot(snap.id, snap.snapname)}
                                                                                    disabled={snapshotLoading}
                                                                                    className="p-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition-colors disabled:opacity-50"
                                                                                    title={t('delete')}
                                                                                >
                                                                                    <Icons.Trash />
                                                                                </button>
                                                                            </div>
                                                                        )}
                                                                        {isInvalidated && (
                                                                            <button
                                                                                onClick={() => handleDeleteEfficientSnapshot(snap.id, snap.snapname)}
                                                                                disabled={snapshotLoading}
                                                                                className="p-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition-colors disabled:opacity-50"
                                                                                title={t('delete')}
                                                                            >
                                                                                <Icons.Trash />
                                                                            </button>
                                                                        )}
                                                                    </div>
                                                                    {/* Per-disk usage bars */}
                                                                    {!isInvalidated && snap.disks?.length > 0 && (
                                                                        <div className="mt-2 space-y-1.5">
                                                                            {snap.disks.map(disk => {
                                                                                const pct = disk.snap_used_percent || 0;
                                                                                const barColor = pct >= 80 ? (pct >= 95 ? 'bg-red-500' : 'bg-yellow-500') : 'bg-green-500';
                                                                                return (
                                                                                    <div key={disk.disk_key} className="text-xs">
                                                                                        <div className="flex justify-between text-gray-400 mb-0.5">
                                                                                            <span>{disk.disk_key} ({disk.original_lv})</span>
                                                                                            <span className={pct >= 80 ? (pct >= 95 ? 'text-red-400' : 'text-yellow-400') : 'text-gray-400'}>
                                                                                                {pct.toFixed(1)}% {t('snapshotUsage')}
                                                                                                {pct >= 80 && ' ⚠'}
                                                                                            </span>
                                                                                        </div>
                                                                                        <div className="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
                                                                                            <div className={`h-full ${barColor} rounded-full transition-all`} style={{width: `${Math.min(100, pct)}%`}}></div>
                                                                                        </div>
                                                                                    </div>
                                                                                );
                                                                            })}
                                                                            {snap.disks.some(d => (d.snap_used_percent || 0) >= 80) && (
                                                                                <div className="text-xs text-yellow-400 flex items-center gap-1 mt-1">
                                                                                    <Icons.AlertTriangle />
                                                                                    {t('snapshotOverflow')}
                                                                                </div>
                                                                            )}
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            );
                                                        })}
                                                    </div>
                                                </div>
                                            )}

                                            {/* Create Snapshot Modal */}
                                            {showCreateSnapshot && (
                                                <CreateSnapshotModal
                                                    isQemu={isQemu}
                                                    onSubmit={handleCreateSnapshot}
                                                    onClose={() => setShowCreateSnapshot(false)}
                                                    loading={snapshotLoading}
                                                    efficientInfo={efficientInfo}
                                                />
                                            )}
                                        </div>
                                    )}
                                    
                                    {/* LW: Backups Tab - Dec 2025 */}
                                    {activeTab === 'backups' && (
                                        <div className="space-y-6">
                                            <div className="flex items-center justify-between">
                                                <h3 className="text-sm font-semibold text-gray-300">{t('backupsTab') || 'Backups'}</h3>
                                                <div className="flex items-center gap-2">
                                                    <button
                                                        onClick={fetchBackups}
                                                        disabled={backupLoading}
                                                        className="p-2 hover:bg-proxmox-hover rounded-lg text-gray-400"
                                                        title={t('refresh')}
                                                    >
                                                        <Icons.RotateCw className={backupLoading ? 'animate-spin' : ''} />
                                                    </button>
                                                    <button
                                                        onClick={() => setShowCreateBackup(true)}
                                                        className="flex items-center gap-2 px-3 py-1.5 bg-green-600 rounded-lg text-white text-sm hover:bg-green-700"
                                                    >
                                                        <Icons.Plus />
                                                        {t('createBackup') || 'Create Backup'}
                                                    </button>
                                                </div>
                                            </div>
                                            
                                            {backupLoading ? (
                                                <div className="flex items-center justify-center py-8">
                                                    <Icons.RotateCw className="animate-spin text-gray-400" />
                                                </div>
                                            ) : vmBackups.length > 0 ? (
                                                <div className="space-y-3">
                                                    {vmBackups.map(backup => (
                                                        <div key={backup.volid} className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                            <div className="flex items-center justify-between">
                                                                <div className="flex items-center gap-3">
                                                                    <div className="p-2 bg-purple-500/10 rounded-lg">
                                                                        <Icons.Database className="text-purple-400" />
                                                                    </div>
                                                                    <div>
                                                                        <div className="font-medium text-white">{backup.filename}</div>
                                                                        <div className="text-xs text-gray-400">
                                                                            {backup.ctime ? new Date(backup.ctime * 1000).toLocaleString() : ''}
                                                                            <span className="mx-2">•</span>
                                                                            {(backup.size / (1024*1024*1024)).toFixed(2)} GB
                                                                            <span className="mx-2">•</span>
                                                                            <span className="text-gray-500">{backup.storage}</span>
                                                                        </div>
                                                                        {backup.notes && (
                                                                            <div className="text-sm text-gray-500 mt-1">{backup.notes}</div>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                                <div className="flex items-center gap-2">
                                                                    <button
                                                                        onClick={() => setShowRestoreBackup(backup)}
                                                                        disabled={backupLoading}
                                                                        className="p-2 rounded-lg bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 transition-colors disabled:opacity-50"
                                                                        title={t('restore') || 'Restore'}
                                                                    >
                                                                        <Icons.RotateCcw />
                                                                    </button>
                                                                    <button
                                                                        onClick={() => handleDeleteBackup(backup.volid)}
                                                                        disabled={backupLoading}
                                                                        className="p-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition-colors disabled:opacity-50"
                                                                        title={t('delete')}
                                                                    >
                                                                        <Icons.Trash />
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            ) : (
                                                <div className="text-center py-8 text-gray-500">
                                                    <Icons.Database className="mx-auto opacity-50" />
                                                    <p className="mt-2">{t('noBackups') || 'No backups found'}</p>
                                                    <p className="text-xs mt-1">{t('noBackupsHint') || 'Create a backup or check your backup storages'}</p>
                                                </div>
                                            )}
                                            
                                            {/* MK: Create Backup Modal */}
                                            {showCreateBackup && (
                                                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 w-full max-w-md">
                                                        <h3 className="text-lg font-semibold mb-4">{t('createBackup') || 'Create Backup'}</h3>
                                                        <div className="space-y-4">
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-2">{t('storage') || 'Storage'}</label>
                                                                <select
                                                                    id="backup-storage"
                                                                    defaultValue="local"
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                >
                                                                    {storageList.filter(s => s.content?.includes('backup')).map(s => (
                                                                        <option key={s.storage} value={s.storage}>{s.storage}</option>
                                                                    ))}
                                                                    {!storageList.some(s => s.content?.includes('backup')) && (
                                                                        <option value="local">local</option>
                                                                    )}
                                                                </select>
                                                            </div>
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-2">{t('backupMode') || 'Mode'}</label>
                                                                <select
                                                                    id="backup-mode"
                                                                    defaultValue="snapshot"
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                >
                                                                    <option value="snapshot">{t('backupModeSnapshot') || 'Snapshot (no stop)'}</option>
                                                                    <option value="suspend">{t('backupModeSuspend') || 'Suspend (brief pause)'}</option>
                                                                    <option value="stop">{t('backupModeStop') || 'Stop (VM will stop)'}</option>
                                                                </select>
                                                            </div>
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-2">{t('compression') || 'Compression'}</label>
                                                                <select
                                                                    id="backup-compress"
                                                                    defaultValue="zstd"
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                >
                                                                    <option value="zstd">{t('compressZstd') || 'ZSTD (recommended)'}</option>
                                                                    <option value="lzo">{t('compressLzo') || 'LZO (fast)'}</option>
                                                                    <option value="gzip">{t('compressGzip') || 'GZIP'}</option>
                                                                    <option value="0">{t('compressNone') || 'None'}</option>
                                                                </select>
                                                            </div>
                                                            {/* NS: Notes/Description field */}
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-2">{t('backupNotes') || 'Notes (optional)'}</label>
                                                                <textarea
                                                                    id="backup-notes"
                                                                    placeholder={t('backupNotesPlaceholder') || 'e.g. Before major update, weekly backup...'}
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white resize-none"
                                                                    rows={2}
                                                                />
                                                            </div>
                                                            <div className="flex gap-2 justify-end pt-2">
                                                                <button
                                                                    onClick={() => setShowCreateBackup(false)}
                                                                    className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg"
                                                                >
                                                                    {t('cancel')}
                                                                </button>
                                                                <button
                                                                    onClick={() => {
                                                                        const storage = document.getElementById('backup-storage').value;
                                                                        const mode = document.getElementById('backup-mode').value;
                                                                        const compress = document.getElementById('backup-compress').value;
                                                                        const notes = document.getElementById('backup-notes').value;
                                                                        handleCreateBackup(storage, mode, compress, notes);
                                                                    }}
                                                                    disabled={backupLoading}
                                                                    className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg disabled:opacity-50"
                                                                >
                                                                    {backupLoading ? t('loading') : t('create') || 'Create'}
                                                                </button>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            )}
                                            
                                            {/* NS: Restore Backup Modal */}
                                            {showRestoreBackup && (
                                                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 w-full max-w-md">
                                                        <h3 className="text-lg font-semibold mb-4">{t('restoreBackup') || 'Restore Backup'}</h3>
                                                        <div className="space-y-4">
                                                            <div className="p-3 bg-proxmox-dark rounded-lg">
                                                                <p className="text-sm text-gray-400">{t('selectedBackup') || 'Selected Backup'}:</p>
                                                                <p className="font-mono text-sm truncate">{showRestoreBackup.filename}</p>
                                                            </div>
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-2">{t('targetVmid') || 'Target VMID'}</label>
                                                                <input
                                                                    type="number"
                                                                    id="restore-vmid"
                                                                    defaultValue={vm.vmid}
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                />
                                                                <p className="text-xs text-yellow-400 mt-1">
                                                                    {t('sameVmidWarning') || 'Same VMID = VM will be overwritten!'}
                                                                </p>
                                                            </div>
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-2">{t('targetStorage') || 'Target Storage (optional)'}</label>
                                                                <select
                                                                    id="restore-storage"
                                                                    defaultValue=""
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                >
                                                                    <option value="">{t('originalStorage') || 'Keep original'}</option>
                                                                    {storageList.filter(s => s.content?.includes('images')).map(s => (
                                                                        <option key={s.storage} value={s.storage}>{s.storage}</option>
                                                                    ))}
                                                                </select>
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                <input
                                                                    type="checkbox"
                                                                    id="restore-start"
                                                                    className="w-4 h-4 rounded"
                                                                />
                                                                <label htmlFor="restore-start" className="text-sm text-gray-300">
                                                                    {t('startAfterRestore') || 'Start after restore'}
                                                                </label>
                                                            </div>
                                                            <div className="flex gap-2 justify-end pt-2">
                                                                <button
                                                                    onClick={() => setShowRestoreBackup(null)}
                                                                    className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg"
                                                                >
                                                                    {t('cancel')}
                                                                </button>
                                                                <button
                                                                    onClick={() => {
                                                                        const targetVmid = parseInt(document.getElementById('restore-vmid').value);
                                                                        const storage = document.getElementById('restore-storage').value;
                                                                        const startAfter = document.getElementById('restore-start').checked;
                                                                        handleRestoreBackup(showRestoreBackup.volid, targetVmid, storage, startAfter);
                                                                    }}
                                                                    disabled={backupLoading}
                                                                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50"
                                                                >
                                                                    {backupLoading ? t('loading') : t('restore') || 'Restore'}
                                                                </button>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Replication Tab */}
                                    {activeTab === 'replication' && (
                                        <div className="space-y-6">
                                            <div className="flex items-center justify-between">
                                                <h3 className="text-sm font-semibold text-gray-300">{t('replicationJobs')}</h3>
                                                <button
                                                    onClick={() => setShowCreateReplication(true)}
                                                    disabled={allClusterNodes.length < 2}
                                                    className="flex items-center gap-2 px-3 py-1.5 bg-green-600 rounded-lg text-white text-sm hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
                                                >
                                                    <Icons.Plus />
                                                    {t('createReplication')}
                                                </button>
                                            </div>
                                            
                                            {allClusterNodes.length < 2 && (
                                                <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-sm text-yellow-400">
                                                    ⚠️ {t('replicationNeedsTwoNodes')}
                                                </div>
                                            )}
                                            
                                            {replications.length > 0 ? (
                                                <div className="space-y-3">
                                                    {replications.map(job => (
                                                        <div key={job.id} className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                            <div className="flex items-center justify-between">
                                                                <div className="flex items-center gap-3">
                                                                    <div className={`p-2 rounded-lg ${job.error ? 'bg-red-500/10' : 'bg-green-500/10'}`}>
                                                                        <Icons.RefreshCw />
                                                                    </div>
                                                                    <div>
                                                                        <div className="font-medium text-white">
                                                                            ↑ {job.target}
                                                                        </div>
                                                                        <div className="text-xs text-gray-400">
                                                                            Schedule: {job.schedule || '*/15'} | 
                                                                            {job.last_sync ? ` ${t('lastSync')}: ${new Date(job.last_sync * 1000).toLocaleString()}` : ` ${t('neverSynced')}`}
                                                                        </div>
                                                                        {job.error && (
                                                                            <div className="text-xs text-red-400 mt-1">{t('error')}: {job.error}</div>
                                                                        )}
                                                                        {job.comment && (
                                                                            <div className="text-sm text-gray-500 mt-1">{job.comment}</div>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                                <div className="flex items-center gap-2">
                                                                    <button
                                                                        onClick={() => handleRunReplicationNow(job.id)}
                                                                        disabled={replicationLoading}
                                                                        className="p-2 rounded-lg bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 transition-colors disabled:opacity-50"
                                                                        title={t('syncNow')}
                                                                    >
                                                                        <Icons.PlayCircle />
                                                                    </button>
                                                                    <button
                                                                        onClick={() => handleDeleteReplication(job.id)}
                                                                        disabled={replicationLoading}
                                                                        className="p-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition-colors disabled:opacity-50"
                                                                        title={t('delete')}
                                                                    >
                                                                        <Icons.Trash />
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            ) : (
                                                <div className="text-center py-8 text-gray-500">
                                                    <Icons.RefreshCw />
                                                    <p className="mt-2">{t('noReplicationJobs')}</p>
                                                </div>
                                            )}

                                            {/* Create Replication Modal */}
                                            {showCreateReplication && (
                                                <CreateReplicationModal
                                                    nodes={clusterNodes}
                                                    onSubmit={handleCreateReplication}
                                                    onClose={() => setShowCreateReplication(false)}
                                                    loading={replicationLoading}
                                                />
                                            )}

                                            {/* NS: Cross-cluster replication - DR to other clusters */}
                                            <div className="mt-6">
                                                <div className="flex items-center justify-between mb-3">
                                                    <h4 className="text-sm font-medium text-gray-300 flex items-center gap-2">
                                                        <Icons.Globe className="w-4 h-4 text-proxmox-orange" />
                                                        {t('crossClusterReplication')}
                                                    </h4>
                                                    <button
                                                        onClick={() => setShowCreateXRepl(true)}
                                                        className="flex items-center gap-1.5 px-3 py-1.5 bg-proxmox-orange/10 text-proxmox-orange rounded-lg text-xs hover:bg-proxmox-orange/20 transition-colors"
                                                    >
                                                        <Icons.Plus className="w-3.5 h-3.5" />
                                                        {t('addDrJob')}
                                                    </button>
                                                </div>

                                                {crossClusterRepls.length === 0 ? (
                                                    <div className="text-center py-6 text-gray-500 text-sm">
                                                        {t('noReplicationJobs')}
                                                    </div>
                                                ) : (
                                                    <div className="space-y-2">
                                                        {crossClusterRepls.map(job => (
                                                            <div key={job.id} className="bg-proxmox-darker rounded-lg p-3 flex items-center justify-between">
                                                                <div className="flex-1">
                                                                    <div className="flex items-center gap-2">
                                                                        <span className={`w-2 h-2 rounded-full ${job.enabled ? 'bg-green-500' : 'bg-gray-500'}`} />
                                                                        <span className="text-sm text-white">&rarr; {job.target_cluster}</span>
                                                                        <span className="text-xs text-gray-500">{job.schedule}</span>
                                                                    </div>
                                                                    <div className="text-xs text-gray-500 mt-1">
                                                                        {job.last_run ? `${t('lastRunPrefix')}: ${new Date(job.last_run).toLocaleString()}` : t('neverRun')}
                                                                        {job.last_status && ` \u00b7 ${job.last_status}`}
                                                                        {job.last_error && <span className="text-red-400 ml-1">{job.last_error}</span>}
                                                                    </div>
                                                                </div>
                                                                <div className="flex gap-1">
                                                                    <button onClick={() => handleRunXReplNow(job.id)} className="p-1.5 rounded hover:bg-green-500/10 text-gray-400 hover:text-green-400" title={t('runNow')}>
                                                                        <Icons.Play className="w-3.5 h-3.5" />
                                                                    </button>
                                                                    <button onClick={() => handleDeleteXRepl(job.id)} className="p-1.5 rounded hover:bg-red-500/10 text-gray-400 hover:text-red-400" title={t('delete')}>
                                                                        <Icons.Trash className="w-3.5 h-3.5" />
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}

                                                {/* MK: inline form for new cross-cluster job */}
                                                {showCreateXRepl && (
                                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-lg p-4 mt-3">
                                                        <h5 className="text-sm font-medium mb-3">{t('newCrossClusterReplication')}</h5>
                                                        <div className="grid grid-cols-2 gap-3">
                                                            <div>
                                                                <label className="block text-xs text-gray-400 mb-1">{t('targetCluster')}</label>
                                                                <select
                                                                    value={xReplForm.target_cluster}
                                                                    onChange={e => setXReplForm(f => ({ ...f, target_cluster: e.target.value, target_storage: '', target_bridge: 'vmbr0' }))}
                                                                    className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                >
                                                                    <option value="">{t('selectCluster') || 'Select cluster...'}</option>
                                                                    {allClusters.filter(c => c.id !== clusterId && c.connected).map(c => (
                                                                        <option key={c.id} value={c.id}>{c.name}</option>
                                                                    ))}
                                                                </select>
                                                            </div>
                                                            <div>
                                                                <label className="block text-xs text-gray-400 mb-1">{t('targetStorage')}</label>
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
                                                            <div>
                                                                <label className="block text-xs text-gray-400 mb-1">{t('targetBridge')}</label>
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
                                                            <div>
                                                                <label className="block text-xs text-gray-400 mb-1">{t('scheduleCron')}</label>
                                                                <input
                                                                    type="text"
                                                                    value={xReplForm.schedule}
                                                                    onChange={e => setXReplForm(f => ({ ...f, schedule: e.target.value }))}
                                                                    placeholder="0 */6 * * *"
                                                                    className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                                />
                                                            </div>
                                                            <div>
                                                                <label className="block text-xs text-gray-400 mb-1">{t('replicationRetention')}</label>
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
                                                            <button onClick={handleCreateXRepl} className="px-3 py-1.5 bg-proxmox-orange text-white rounded-lg text-sm hover:bg-proxmox-orange/90 transition-colors">{t('create')}</button>
                                                            <button onClick={() => setShowCreateXRepl(false)} className="px-3 py-1.5 bg-proxmox-dark border border-proxmox-border text-gray-300 rounded-lg text-sm hover:bg-proxmox-darker transition-colors">{t('cancel')}</button>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    )}

                                    {/* History Tab - MK Jan 2026 */}
                                    {activeTab === 'history' && (
                                        <div className="space-y-4">
                                            {/* Sub-tabs */}
                                            <div className="flex gap-2 border-b border-proxmox-border pb-2">
                                                <button 
                                                    onClick={() => { setHistorySubTab('proxmox'); fetchHistory(); }}
                                                    className={`px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${historySubTab === 'proxmox' ? 'bg-proxmox-orange text-white' : 'text-gray-400 hover:text-white hover:bg-proxmox-dark'}`}
                                                >
                                                    {t('proxmoxTasks')}
                                                </button>
                                                <button 
                                                    onClick={() => { setHistorySubTab('pegaprox'); fetchHistory(); }}
                                                    className={`px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${historySubTab === 'pegaprox' ? 'bg-proxmox-orange text-white' : 'text-gray-400 hover:text-white hover:bg-proxmox-dark'}`}
                                                >
                                                    {t('pegaproxActions')}
                                                </button>
                                                <button 
                                                    onClick={fetchHistory}
                                                    className="ml-auto p-2 hover:bg-proxmox-dark rounded-lg text-gray-400 hover:text-white"
                                                    title="Refresh"
                                                >
                                                    <Icons.RefreshCw className={`w-4 h-4 ${historyLoading ? 'animate-spin' : ''}`} />
                                                </button>
                                            </div>

                                            {historyLoading ? (
                                                <div className="flex items-center justify-center py-8">
                                                    <Icons.RotateCw className="w-6 h-6 animate-spin text-proxmox-orange" />
                                                </div>
                                            ) : (
                                                <>
                                                    {/* Proxmox Tasks */}
                                                    {historySubTab === 'proxmox' && (
                                                        <div className="space-y-2">
                                                            <h4 className="text-sm font-medium text-gray-400 mb-2">Proxmox Tasks for {isQemu ? 'VM' : 'CT'} {vm.vmid}</h4>
                                                            {vmProxmoxTasks && vmProxmoxTasks.length > 0 ? (
                                                                <div className="overflow-x-auto max-h-96 overflow-y-auto">
                                                                    <table className="w-full text-sm">
                                                                        <thead className="sticky top-0 bg-proxmox-dark">
                                                                            <tr className="text-left text-gray-400">
                                                                                <th className="p-2">Time</th>
                                                                                <th className="p-2">Type</th>
                                                                                <th className="p-2">User</th>
                                                                                <th className="p-2">Status</th>
                                                                                <th className="p-2">Node</th>
                                                                            </tr>
                                                                        </thead>
                                                                        <tbody>
                                                                            {vmProxmoxTasks.map((task, idx) => (
                                                                                <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                                                    <td className="p-2 text-gray-300 whitespace-nowrap">
                                                                                        {task.starttime ? new Date(task.starttime * 1000).toLocaleString() : '-'}
                                                                                    </td>
                                                                                    <td className="p-2 font-mono text-xs">
                                                                                        <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded">{task.type || '-'}</span>
                                                                                    </td>
                                                                                    <td className="p-2 text-gray-300">{task.user || '-'}</td>
                                                                                    <td className="p-2">
                                                                                        <span className={`px-2 py-0.5 rounded text-xs ${
                                                                                            task.status === 'OK' ? 'bg-green-500/20 text-green-400' :
                                                                                            task.status && task.status.includes('ERROR') ? 'bg-red-500/20 text-red-400' :
                                                                                            task.exitstatus === 'OK' ? 'bg-green-500/20 text-green-400' :
                                                                                            !task.endtime ? 'bg-yellow-500/20 text-yellow-400' :
                                                                                            'bg-gray-500/20 text-gray-400'
                                                                                        }`}>
                                                                                            {task.status || task.exitstatus || (task.endtime ? 'completed' : 'running')}
                                                                                        </span>
                                                                                    </td>
                                                                                    <td className="p-2 text-gray-400 font-mono text-xs">{task.node || vm.node}</td>
                                                                                </tr>
                                                                            ))}
                                                                        </tbody>
                                                                    </table>
                                                                </div>
                                                            ) : (
                                                                <div className="text-center py-8 text-gray-500">
                                                                    <Icons.List className="w-8 h-8 mx-auto mb-2 opacity-50" />
                                                                    <p>No Proxmox tasks found for this {isQemu ? 'VM' : 'Container'}</p>
                                                                </div>
                                                            )}
                                                        </div>
                                                    )}

                                                    {/* PegaProx Actions */}
                                                    {historySubTab === 'pegaprox' && (
                                                        <div className="space-y-2">
                                                            <h4 className="text-sm font-medium text-gray-400 mb-2">PegaProx Actions for {isQemu ? 'VM' : 'CT'} {vm.vmid}</h4>
                                                            {vmPegaproxActions && vmPegaproxActions.length > 0 ? (
                                                                <div className="overflow-x-auto max-h-96 overflow-y-auto">
                                                                    <table className="w-full text-sm">
                                                                        <thead className="sticky top-0 bg-proxmox-dark">
                                                                            <tr className="text-left text-gray-400">
                                                                                <th className="p-2">Time</th>
                                                                                <th className="p-2">Action</th>
                                                                                <th className="p-2">User</th>
                                                                                <th className="p-2">Details</th>
                                                                            </tr>
                                                                        </thead>
                                                                        <tbody>
                                                                            {vmPegaproxActions.map((action, idx) => (
                                                                                <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                                                    <td className="p-2 text-gray-300 whitespace-nowrap">
                                                                                        {action.timestamp ? new Date(action.timestamp).toLocaleString() : '-'}
                                                                                    </td>
                                                                                    <td className="p-2">
                                                                                        <span className="px-2 py-0.5 bg-proxmox-orange/20 text-proxmox-orange rounded text-xs font-mono">
                                                                                            {action.action || '-'}
                                                                                        </span>
                                                                                    </td>
                                                                                    <td className="p-2 text-gray-300 font-medium">{action.user || '-'}</td>
                                                                                    <td className="p-2 text-gray-400 text-xs max-w-xs truncate" title={action.details || ''}>
                                                                                        {action.details || '-'}
                                                                                    </td>
                                                                                </tr>
                                                                            ))}
                                                                        </tbody>
                                                                    </table>
                                                                </div>
                                                            ) : (
                                                                <div className="text-center py-8 text-gray-500">
                                                                    <Icons.List className="w-8 h-8 mx-auto mb-2 opacity-50" />
                                                                    <p>No PegaProx actions found for this {isQemu ? 'VM' : 'Container'}</p>
                                                                </div>
                                                            )}
                                                        </div>
                                                    )}
                                                </>
                                            )}
                                        </div>
                                    )}

                                    {activeTab === 'firewall' && (
                                        <div className="space-y-6">
                                            {fwLoading ? (
                                                <div className="flex items-center justify-center py-12">
                                                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-proxmox-orange"></div>
                                                </div>
                                            ) : (
                                                <>
                                                    {/* Sub-tabs for firewall sections */}
                                                    <div className="flex gap-1 border-b border-proxmox-border pb-2">
                                                        {['rules', 'options', 'aliases', 'ipsets', 'log'].map(st => (
                                                            <button
                                                                key={st}
                                                                onClick={() => { setFwSubTab(st); if (st === 'log') fetchFwLog(); }}
                                                                className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                                                                    fwSubTab === st
                                                                        ? 'bg-proxmox-orange text-white'
                                                                        : 'text-gray-400 hover:text-white hover:bg-proxmox-dark'
                                                                }`}
                                                            >
                                                                {st === 'rules' ? t('firewallRules') || 'Rules' :
                                                                 st === 'options' ? t('firewallOptions') || 'Options' :
                                                                 st === 'aliases' ? t('aliases') || 'Aliases' :
                                                                 st === 'ipsets' ? 'IP Sets' :
                                                                 t('log') || 'Log'}
                                                            </button>
                                                        ))}
                                                    </div>

                                                    {/* Rules Sub-Tab */}
                                                    {fwSubTab === 'rules' && (
                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                            <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                                <h3 className="font-semibold">{t('firewallRules') || 'Firewall Rules'}</h3>
                                                                <button
                                                                    onClick={() => setShowAddFwRule(true)}
                                                                    className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white transition-colors"
                                                                >
                                                                    <Icons.Plus /> {t('add')}
                                                                </button>
                                                            </div>
                                                            <div className="overflow-x-auto">
                                                                <table className="w-full">
                                                                    <thead className="bg-proxmox-dark">
                                                                        <tr>
                                                                            <th className="text-left p-3 text-sm text-gray-400">#</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400">{t('type')}</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400">{t('action')}</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400">Macro</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400">{t('source')}</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400">Dest</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400">Proto</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400">Port</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400">{t('enabled')}</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400">{t('comment')}</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400"></th>
                                                                        </tr>
                                                                    </thead>
                                                                    <tbody>
                                                                        {(!fwRules || fwRules.length === 0) ? (
                                                                            <tr><td colSpan="11" className="p-8 text-center text-gray-500">{t('noFirewallRules') || 'No firewall rules configured'}</td></tr>
                                                                        ) : (Array.isArray(fwRules) ? fwRules : []).map((rule, idx) => (
                                                                            <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                                                <td className="p-3 text-gray-400">{rule.pos}</td>
                                                                                <td className="p-3">
                                                                                    <span className={`px-2 py-0.5 rounded text-xs ${
                                                                                        rule.type === 'in' ? 'bg-blue-500/20 text-blue-400' :
                                                                                        rule.type === 'out' ? 'bg-purple-500/20 text-purple-400' :
                                                                                        'bg-yellow-500/20 text-yellow-400'
                                                                                    }`}>
                                                                                        {(rule.type || 'in').toUpperCase()}
                                                                                    </span>
                                                                                </td>
                                                                                <td className="p-3">
                                                                                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                                                                                        rule.action === 'ACCEPT' ? 'bg-green-500/20 text-green-400' :
                                                                                        rule.action === 'DROP' ? 'bg-red-500/20 text-red-400' :
                                                                                        'bg-yellow-500/20 text-yellow-400'
                                                                                    }`}>
                                                                                        {rule.action}
                                                                                    </span>
                                                                                </td>
                                                                                <td className="p-3 text-gray-300">{rule.macro || '-'}</td>
                                                                                <td className="p-3 font-mono text-xs text-gray-300">{rule.source || '-'}</td>
                                                                                <td className="p-3 font-mono text-xs text-gray-300">{rule.dest || '-'}</td>
                                                                                <td className="p-3 text-gray-300">{rule.proto || '-'}</td>
                                                                                <td className="p-3 font-mono text-xs text-gray-300">{rule.dport || '-'}</td>
                                                                                <td className="p-3">
                                                                                    <button
                                                                                        onClick={async () => {
                                                                                            try {
                                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/rules/${rule.pos}`, {
                                                                                                    method: 'PUT',
                                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                                    body: JSON.stringify({ enable: rule.enable ? 0 : 1 })
                                                                                                });
                                                                                                if (res?.ok) {
                                                                                                    setFwRules(prev => prev.map(r =>
                                                                                                        r.pos === rule.pos ? { ...r, enable: rule.enable ? 0 : 1 } : r
                                                                                                    ));
                                                                                                }
                                                                                            } catch (e) {}
                                                                                        }}
                                                                                        className={`w-8 h-5 rounded-full transition-colors ${rule.enable ? 'bg-green-500' : 'bg-gray-600'}`}
                                                                                    >
                                                                                        <div className={`w-4 h-4 rounded-full bg-white transition-transform ${rule.enable ? 'translate-x-3.5' : 'translate-x-0.5'}`}></div>
                                                                                    </button>
                                                                                </td>
                                                                                <td className="p-3 text-gray-500 text-xs max-w-32 truncate">{rule.comment || ''}</td>
                                                                                <td className="p-3">
                                                                                    <button
                                                                                        onClick={async () => {
                                                                                            if (!confirm(t('confirmDeleteRule') || 'Delete this firewall rule?')) return;
                                                                                            try {
                                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/rules/${rule.pos}`, { method: 'DELETE' });
                                                                                                if (res?.ok) fetchFirewallData();
                                                                                            } catch (e) {}
                                                                                        }}
                                                                                        className="p-1.5 hover:bg-red-500/20 rounded text-red-400 transition-colors"
                                                                                    >
                                                                                        <Icons.Trash />
                                                                                    </button>
                                                                                </td>
                                                                            </tr>
                                                                        ))}
                                                                    </tbody>
                                                                </table>
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Options Sub-Tab */}
                                                    {fwSubTab === 'options' && (
                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                                            <h3 className="font-semibold flex items-center gap-2 mb-4">
                                                                <Icons.Shield />
                                                                {t('firewallOptions') || 'Firewall Options'}
                                                            </h3>
                                                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                                                <div className="bg-proxmox-dark rounded-lg p-4">
                                                                    <div className="text-sm text-gray-400 mb-2">{t('fwEnable') || 'Firewall'}</div>
                                                                    <button
                                                                        onClick={async () => {
                                                                            const newVal = fwOptions.enable ? 0 : 1;
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/options`, {
                                                                                    method: 'PUT',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify({ enable: newVal })
                                                                                });
                                                                                if (res?.ok) setFwOptions(prev => ({ ...prev, enable: newVal }));
                                                                            } catch (e) {}
                                                                        }}
                                                                        className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                                                                            fwOptions.enable
                                                                                ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                                                                                : 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
                                                                        }`}
                                                                    >
                                                                        {fwOptions.enable ? t('enabled') || 'Enabled' : t('disabled') || 'Disabled'}
                                                                    </button>
                                                                </div>
                                                                <div className="bg-proxmox-dark rounded-lg p-4">
                                                                    <div className="text-sm text-gray-400 mb-1">Policy In</div>
                                                                    <select
                                                                        value={fwOptions.policy_in || 'DROP'}
                                                                        onChange={async (e) => {
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/options`, {
                                                                                    method: 'PUT',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify({ policy_in: e.target.value })
                                                                                });
                                                                                if (res?.ok) setFwOptions(prev => ({ ...prev, policy_in: e.target.value }));
                                                                            } catch (e) {}
                                                                        }}
                                                                        className="w-full bg-proxmox-darker border border-proxmox-border rounded-lg p-2 text-white"
                                                                    >
                                                                        <option value="ACCEPT">ACCEPT</option>
                                                                        <option value="DROP">DROP</option>
                                                                        <option value="REJECT">REJECT</option>
                                                                    </select>
                                                                </div>
                                                                <div className="bg-proxmox-dark rounded-lg p-4">
                                                                    <div className="text-sm text-gray-400 mb-1">Policy Out</div>
                                                                    <select
                                                                        value={fwOptions.policy_out || 'ACCEPT'}
                                                                        onChange={async (e) => {
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/options`, {
                                                                                    method: 'PUT',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify({ policy_out: e.target.value })
                                                                                });
                                                                                if (res?.ok) setFwOptions(prev => ({ ...prev, policy_out: e.target.value }));
                                                                            } catch (e) {}
                                                                        }}
                                                                        className="w-full bg-proxmox-darker border border-proxmox-border rounded-lg p-2 text-white"
                                                                    >
                                                                        <option value="ACCEPT">ACCEPT</option>
                                                                        <option value="DROP">DROP</option>
                                                                        <option value="REJECT">REJECT</option>
                                                                    </select>
                                                                </div>
                                                                <div className="bg-proxmox-dark rounded-lg p-4">
                                                                    <div className="text-sm text-gray-400 mb-1">{t('fwDhcp') || 'DHCP'}</div>
                                                                    <button
                                                                        onClick={async () => {
                                                                            const newVal = fwOptions.dhcp ? 0 : 1;
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/options`, {
                                                                                    method: 'PUT',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify({ dhcp: newVal })
                                                                                });
                                                                                if (res?.ok) setFwOptions(prev => ({ ...prev, dhcp: newVal }));
                                                                            } catch (e) {}
                                                                        }}
                                                                        className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                                                                            fwOptions.dhcp ? 'bg-green-500/20 text-green-400' : 'bg-gray-600/30 text-gray-400'
                                                                        }`}
                                                                    >
                                                                        {fwOptions.dhcp ? 'On' : 'Off'}
                                                                    </button>
                                                                </div>
                                                                <div className="bg-proxmox-dark rounded-lg p-4">
                                                                    <div className="text-sm text-gray-400 mb-1">{t('fwNdp') || 'NDP'}</div>
                                                                    <button
                                                                        onClick={async () => {
                                                                            const newVal = fwOptions.ndp ? 0 : 1;
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/options`, {
                                                                                    method: 'PUT',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify({ ndp: newVal })
                                                                                });
                                                                                if (res?.ok) setFwOptions(prev => ({ ...prev, ndp: newVal }));
                                                                            } catch (e) {}
                                                                        }}
                                                                        className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                                                                            fwOptions.ndp ? 'bg-green-500/20 text-green-400' : 'bg-gray-600/30 text-gray-400'
                                                                        }`}
                                                                    >
                                                                        {fwOptions.ndp ? 'On' : 'Off'}
                                                                    </button>
                                                                </div>
                                                                <div className="bg-proxmox-dark rounded-lg p-4">
                                                                    <div className="text-sm text-gray-400 mb-1">{t('fwRadv') || 'Router Adv.'}</div>
                                                                    <button
                                                                        onClick={async () => {
                                                                            const newVal = fwOptions.radv ? 0 : 1;
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/options`, {
                                                                                    method: 'PUT',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify({ radv: newVal })
                                                                                });
                                                                                if (res?.ok) setFwOptions(prev => ({ ...prev, radv: newVal }));
                                                                            } catch (e) {}
                                                                        }}
                                                                        className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                                                                            fwOptions.radv ? 'bg-green-500/20 text-green-400' : 'bg-gray-600/30 text-gray-400'
                                                                        }`}
                                                                    >
                                                                        {fwOptions.radv ? 'On' : 'Off'}
                                                                    </button>
                                                                </div>
                                                                <div className="bg-proxmox-dark rounded-lg p-4">
                                                                    <div className="text-sm text-gray-400 mb-1">{t('fwMacFilter') || 'MAC Filter'}</div>
                                                                    <button
                                                                        onClick={async () => {
                                                                            const newVal = fwOptions.macfilter ? 0 : 1;
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/options`, {
                                                                                    method: 'PUT',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify({ macfilter: newVal })
                                                                                });
                                                                                if (res?.ok) setFwOptions(prev => ({ ...prev, macfilter: newVal }));
                                                                            } catch (e) {}
                                                                        }}
                                                                        className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                                                                            fwOptions.macfilter ? 'bg-green-500/20 text-green-400' : 'bg-gray-600/30 text-gray-400'
                                                                        }`}
                                                                    >
                                                                        {fwOptions.macfilter ? 'On' : 'Off'}
                                                                    </button>
                                                                </div>
                                                                <div className="bg-proxmox-dark rounded-lg p-4">
                                                                    <div className="text-sm text-gray-400 mb-1">{t('fwLogLevel') || 'Log Level In'}</div>
                                                                    <select
                                                                        value={fwOptions.log_level_in || 'nolog'}
                                                                        onChange={async (e) => {
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/options`, {
                                                                                    method: 'PUT',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify({ log_level_in: e.target.value })
                                                                                });
                                                                                if (res?.ok) setFwOptions(prev => ({ ...prev, log_level_in: e.target.value }));
                                                                            } catch (e) {}
                                                                        }}
                                                                        className="w-full bg-proxmox-darker border border-proxmox-border rounded-lg p-2 text-white"
                                                                    >
                                                                        <option value="nolog">No Log</option>
                                                                        <option value="emerg">Emergency</option>
                                                                        <option value="alert">Alert</option>
                                                                        <option value="crit">Critical</option>
                                                                        <option value="err">Error</option>
                                                                        <option value="warning">Warning</option>
                                                                        <option value="notice">Notice</option>
                                                                        <option value="info">Info</option>
                                                                        <option value="debug">Debug</option>
                                                                    </select>
                                                                </div>
                                                                <div className="bg-proxmox-dark rounded-lg p-4">
                                                                    <div className="text-sm text-gray-400 mb-1">{t('fwLogLevelOut') || 'Log Level Out'}</div>
                                                                    <select
                                                                        value={fwOptions.log_level_out || 'nolog'}
                                                                        onChange={async (e) => {
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/options`, {
                                                                                    method: 'PUT',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify({ log_level_out: e.target.value })
                                                                                });
                                                                                if (res?.ok) setFwOptions(prev => ({ ...prev, log_level_out: e.target.value }));
                                                                            } catch (e) {}
                                                                        }}
                                                                        className="w-full bg-proxmox-darker border border-proxmox-border rounded-lg p-2 text-white"
                                                                    >
                                                                        <option value="nolog">No Log</option>
                                                                        <option value="emerg">Emergency</option>
                                                                        <option value="alert">Alert</option>
                                                                        <option value="crit">Critical</option>
                                                                        <option value="err">Error</option>
                                                                        <option value="warning">Warning</option>
                                                                        <option value="notice">Notice</option>
                                                                        <option value="info">Info</option>
                                                                        <option value="debug">Debug</option>
                                                                    </select>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Aliases Sub-Tab */}
                                                    {fwSubTab === 'aliases' && (
                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                            <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                                <h3 className="font-semibold">{t('aliases') || 'Aliases'}</h3>
                                                                <button
                                                                    onClick={() => setShowAddFwAlias(true)}
                                                                    className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white transition-colors"
                                                                >
                                                                    <Icons.Plus /> {t('add')}
                                                                </button>
                                                            </div>
                                                            <div className="overflow-x-auto">
                                                                <table className="w-full">
                                                                    <thead className="bg-proxmox-dark">
                                                                        <tr>
                                                                            <th className="text-left p-3 text-sm text-gray-400">{t('name')}</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400">CIDR</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400">{t('comment')}</th>
                                                                            <th className="text-left p-3 text-sm text-gray-400"></th>
                                                                        </tr>
                                                                    </thead>
                                                                    <tbody>
                                                                        {(!fwAliases || fwAliases.length === 0) ? (
                                                                            <tr><td colSpan="4" className="p-8 text-center text-gray-500">{t('noAliases') || 'No aliases configured'}</td></tr>
                                                                        ) : fwAliases.map((alias, idx) => (
                                                                            <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                                                <td className="p-3 font-medium">{alias.name}</td>
                                                                                <td className="p-3 font-mono text-sm text-gray-300">{alias.cidr}</td>
                                                                                <td className="p-3 text-gray-500 text-sm">{alias.comment || ''}</td>
                                                                                <td className="p-3">
                                                                                    <button
                                                                                        onClick={async () => {
                                                                                            if (!confirm(`Delete alias "${alias.name}"?`)) return;
                                                                                            try {
                                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/aliases/${alias.name}`, { method: 'DELETE' });
                                                                                                if (res?.ok) fetchFirewallData();
                                                                                            } catch (e) {}
                                                                                        }}
                                                                                        className="p-1.5 hover:bg-red-500/20 rounded text-red-400 transition-colors"
                                                                                    >
                                                                                        <Icons.Trash />
                                                                                    </button>
                                                                                </td>
                                                                            </tr>
                                                                        ))}
                                                                    </tbody>
                                                                </table>
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* IP Sets Sub-Tab */}
                                                    {fwSubTab === 'ipsets' && (
                                                        <div className="space-y-4">
                                                            <div className="flex justify-between items-center">
                                                                <h3 className="font-semibold">IP Sets</h3>
                                                                <button
                                                                    onClick={() => setShowAddFwIpset(true)}
                                                                    className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white transition-colors"
                                                                >
                                                                    <Icons.Plus /> {t('add')}
                                                                </button>
                                                            </div>
                                                            {(!fwIpsets || fwIpsets.length === 0) ? (
                                                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-8 text-center text-gray-500">
                                                                    {t('noIpsets') || 'No IP sets configured'}
                                                                </div>
                                                            ) : fwIpsets.map((ipset, idx) => (
                                                                <div key={idx} className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                                    <div
                                                                        className="p-4 flex justify-between items-center cursor-pointer hover:bg-proxmox-dark/50"
                                                                        onClick={() => setExpandedIpset(expandedIpset === ipset.name ? null : ipset.name)}
                                                                    >
                                                                        <div className="flex items-center gap-3">
                                                                            <Icons.ChevronRight className={`w-4 h-4 transition-transform ${expandedIpset === ipset.name ? 'rotate-90' : ''}`} />
                                                                            <span className="font-medium">{ipset.name}</span>
                                                                            {ipset.comment && <span className="text-gray-500 text-sm">- {ipset.comment}</span>}
                                                                        </div>
                                                                        <button
                                                                            onClick={async (e) => {
                                                                                e.stopPropagation();
                                                                                if (!confirm(`Delete IP set "${ipset.name}"?`)) return;
                                                                                try {
                                                                                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/ipset/${ipset.name}`, { method: 'DELETE' });
                                                                                    if (res?.ok) fetchFirewallData();
                                                                                } catch (e) {}
                                                                            }}
                                                                            className="p-1.5 hover:bg-red-500/20 rounded text-red-400 transition-colors"
                                                                        >
                                                                            <Icons.Trash />
                                                                        </button>
                                                                    </div>
                                                                    {expandedIpset === ipset.name && (
                                                                        <div className="border-t border-proxmox-border">
                                                                            <IpsetEntries
                                                                                clusterId={clusterId}
                                                                                vm={vm}
                                                                                ipsetName={ipset.name}
                                                                                authFetch={authFetch}
                                                                                onRefresh={fetchFirewallData}
                                                                                t={t}
                                                                            />
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}

                                                    {/* Log Sub-Tab */}
                                                    {fwSubTab === 'log' && (
                                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                            <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                                <h3 className="font-semibold">{t('firewallLog') || 'Firewall Log'}</h3>
                                                                <button
                                                                    onClick={fetchFwLog}
                                                                    className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg text-sm transition-colors"
                                                                >
                                                                    <Icons.RefreshCw className="w-4 h-4" /> {t('refresh') || 'Refresh'}
                                                                </button>
                                                            </div>
                                                            <div className="p-4 max-h-96 overflow-y-auto">
                                                                {(!fwLog || fwLog.length === 0) ? (
                                                                    <div className="text-center text-gray-500 py-8">{t('noLogEntries') || 'No log entries'}</div>
                                                                ) : (
                                                                    <div className="space-y-1 font-mono text-xs">
                                                                        {(Array.isArray(fwLog) ? fwLog : []).map((entry, idx) => (
                                                                            <div key={idx} className="p-2 bg-proxmox-dark rounded text-gray-300 whitespace-pre-wrap break-all">
                                                                                {typeof entry === 'string' ? entry : (entry.t || entry.n || JSON.stringify(entry))}
                                                                            </div>
                                                                        ))}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Add Rule Modal */}
                                                    {showAddFwRule && (
                                                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop" onClick={() => setShowAddFwRule(false)}>
                                                            <div className="w-full max-w-lg bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
                                                                <div className="p-4 border-b border-proxmox-border">
                                                                    <h3 className="font-semibold">{t('addFirewallRule') || 'Add Firewall Rule'}</h3>
                                                                </div>
                                                                <div className="p-4 space-y-4">
                                                                    <div className="grid grid-cols-2 gap-4">
                                                                        <div>
                                                                            <label className="text-sm text-gray-400 mb-1 block">Direction</label>
                                                                            <select
                                                                                value={newFwRule.type || 'in'}
                                                                                onChange={e => setNewFwRule(p => ({...p, type: e.target.value}))}
                                                                                className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                            >
                                                                                <option value="in">IN</option>
                                                                                <option value="out">OUT</option>
                                                                                <option value="group">GROUP</option>
                                                                            </select>
                                                                        </div>
                                                                        <div>
                                                                            <label className="text-sm text-gray-400 mb-1 block">Action</label>
                                                                            <select
                                                                                value={newFwRule.action || 'ACCEPT'}
                                                                                onChange={e => setNewFwRule(p => ({...p, action: e.target.value}))}
                                                                                className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                            >
                                                                                <option value="ACCEPT">ACCEPT</option>
                                                                                <option value="DROP">DROP</option>
                                                                                <option value="REJECT">REJECT</option>
                                                                            </select>
                                                                        </div>
                                                                    </div>
                                                                    <div className="grid grid-cols-2 gap-4">
                                                                        <div>
                                                                            <label className="text-sm text-gray-400 mb-1 block">Macro</label>
                                                                            <select
                                                                                value={newFwRule.macro || ''}
                                                                                onChange={e => setNewFwRule(p => ({...p, macro: e.target.value || undefined}))}
                                                                                className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                            >
                                                                                <option value="">None</option>
                                                                                {(() => {
                                                                                    const dynamicMacros = (Array.isArray(fwRefs) ? fwRefs : []).filter(r => r.type === 'macro').map(r => r.name);
                                                                                    const allMacros = dynamicMacros.length > 0 ? dynamicMacros : [
                                                                                        'Amanda','Auth','BGP','BitTorrent','Ceph','CephMon','CephOSD','CephMGR','CephMDS',
                                                                                        'DHCPfwd','DHCPv6','DNS','Dropbox','FTP','GNUnet','GRE','HKP',
                                                                                        'HTTP','HTTPS','ICMP','ICMPv6','IMAP','IMAPS','IPsec-ah','IPsec-esp',
                                                                                        'IRC','Jabber','JetDirect','L2TP','LDAP','LDAPS','MDNS','MSSQL',
                                                                                        'MySQL','NFS','NTP','OSPF','OpenVPN','PCA','PMG','POP3','POP3S',
                                                                                        'PPtP','Ping','PostgreSQL','Printer','RDP','RIP','RNDC',
                                                                                        'Razor','Rsh','SANE','SMB','SMBv2','SMTP','SMTPS','SNMP','SPAMD',
                                                                                        'SSH','SVN','SixXS','Squid','Submission','Syslog','TFTP','Telnet',
                                                                                        'Tinc','Traceroute','VNC','VXLAN','Webmin','NFS','Razor'
                                                                                    ];
                                                                                    return allMacros.sort().map(name => (
                                                                                        <option key={name} value={name}>{name}</option>
                                                                                    ));
                                                                                })()}
                                                                            </select>
                                                                        </div>
                                                                        <div>
                                                                            <label className="text-sm text-gray-400 mb-1 block">Interface</label>
                                                                            <select
                                                                                value={newFwRule.iface || ''}
                                                                                onChange={e => setNewFwRule(p => ({...p, iface: e.target.value}))}
                                                                                className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                            >
                                                                                <option value="">Any</option>
                                                                                {(config?.networks || []).map(n => (
                                                                                    <option key={n.id} value={n.id}>{n.id}{n.bridge ? ` (${n.bridge})` : ''}</option>
                                                                                ))}
                                                                                {(!config?.networks || config.networks.length === 0) && (
                                                                                    <>
                                                                                        <option value="net0">net0</option>
                                                                                        <option value="net1">net1</option>
                                                                                    </>
                                                                                )}
                                                                            </select>
                                                                        </div>
                                                                    </div>
                                                                    <div className="grid grid-cols-2 gap-4">
                                                                        <div>
                                                                            <label className="text-sm text-gray-400 mb-1 block">Protocol</label>
                                                                            <select
                                                                                value={newFwRule.proto || ''}
                                                                                onChange={e => setNewFwRule(p => ({...p, proto: e.target.value}))}
                                                                                className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                            >
                                                                                <option value="">Any</option>
                                                                                <option value="tcp">TCP</option>
                                                                                <option value="udp">UDP</option>
                                                                                <option value="icmp">ICMP</option>
                                                                                <option value="sctp">SCTP</option>
                                                                            </select>
                                                                        </div>
                                                                        <div>
                                                                            <label className="text-sm text-gray-400 mb-1 block">Dest. Port</label>
                                                                            <input
                                                                                type="text"
                                                                                value={newFwRule.dport || ''}
                                                                                onChange={e => setNewFwRule(p => ({...p, dport: e.target.value}))}
                                                                                placeholder="e.g. 22, 80, 443"
                                                                                className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                            />
                                                                        </div>
                                                                    </div>
                                                                    <div className="grid grid-cols-2 gap-4">
                                                                        <div>
                                                                            <label className="text-sm text-gray-400 mb-1 block">Source</label>
                                                                            <input
                                                                                type="text"
                                                                                value={newFwRule.source || ''}
                                                                                onChange={e => setNewFwRule(p => ({...p, source: e.target.value}))}
                                                                                placeholder="10.0.0.0/24 or 10.0.0.1"
                                                                                className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                            />
                                                                        </div>
                                                                        <div>
                                                                            <label className="text-sm text-gray-400 mb-1 block">Destination</label>
                                                                            <input
                                                                                type="text"
                                                                                value={newFwRule.dest || ''}
                                                                                onChange={e => setNewFwRule(p => ({...p, dest: e.target.value}))}
                                                                                placeholder="192.168.1.0/24 or 192.168.1.1"
                                                                                className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                            />
                                                                        </div>
                                                                    </div>
                                                                    <div>
                                                                        <label className="text-sm text-gray-400 mb-1 block">Comment</label>
                                                                        <input
                                                                            type="text"
                                                                            value={newFwRule.comment || ''}
                                                                            onChange={e => setNewFwRule(p => ({...p, comment: e.target.value}))}
                                                                            placeholder="Optional description"
                                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                        />
                                                                    </div>
                                                                    <label className="flex items-center gap-2">
                                                                        <input
                                                                            type="checkbox"
                                                                            checked={newFwRule.enable !== 0}
                                                                            onChange={e => setNewFwRule(p => ({...p, enable: e.target.checked ? 1 : 0}))}
                                                                            className="w-4 h-4 rounded"
                                                                        />
                                                                        <span>Enable rule</span>
                                                                    </label>
                                                                </div>
                                                                <div className="p-4 border-t border-proxmox-border flex gap-3 justify-end">
                                                                    <button
                                                                        onClick={() => setShowAddFwRule(false)}
                                                                        className="px-4 py-2 bg-proxmox-dark rounded-lg hover:bg-proxmox-hover transition-colors"
                                                                    >
                                                                        {t('cancel')}
                                                                    </button>
                                                                    <button
                                                                        onClick={async () => {
                                                                            try {
                                                                                const ruleData = { ...newFwRule };
                                                                                Object.keys(ruleData).forEach(k => { if (!ruleData[k] && ruleData[k] !== 0) delete ruleData[k]; });
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/rules`, {
                                                                                    method: 'POST',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify(ruleData)
                                                                                });
                                                                                if (res?.ok) {
                                                                                    fetchFirewallData();
                                                                                    setShowAddFwRule(false);
                                                                                    setNewFwRule({ type: 'in', action: 'ACCEPT', enable: 1 });
                                                                                    if (addToast) addToast(t('firewallRuleCreated') || 'Firewall rule created', 'success');
                                                                                } else {
                                                                                    const err = await res?.json().catch(() => ({}));
                                                                                    let errMsg = 'Failed to create rule';
                                                                                    if (err?.error && typeof err.error === 'object') {
                                                                                        errMsg = Object.entries(err.error).map(([k,v]) => `${k}: ${String(v).trim()}`).join('; ');
                                                                                    } else if (err?.error) {
                                                                                        errMsg = String(err.error);
                                                                                    } else if (err?.message) {
                                                                                        errMsg = String(err.message);
                                                                                    }
                                                                                    if (addToast) addToast(errMsg, 'error');
                                                                                }
                                                                            } catch (e) { if (addToast) addToast('Connection error', 'error'); }
                                                                        }}
                                                                        className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600 transition-colors"
                                                                    >
                                                                        {t('add')}
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Add Alias Modal */}
                                                    {showAddFwAlias && (
                                                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop" onClick={() => setShowAddFwAlias(false)}>
                                                            <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
                                                                <div className="p-4 border-b border-proxmox-border">
                                                                    <h3 className="font-semibold">{t('fwAddAlias') || 'Add Alias'}</h3>
                                                                </div>
                                                                <div className="p-4 space-y-4">
                                                                    <div>
                                                                        <label className="text-sm text-gray-400 mb-1 block">{t('name')}</label>
                                                                        <input
                                                                            type="text"
                                                                            value={newFwAlias.name}
                                                                            onChange={e => setNewFwAlias(p => ({...p, name: e.target.value}))}
                                                                            placeholder="e.g. myserver"
                                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                        />
                                                                    </div>
                                                                    <div>
                                                                        <label className="text-sm text-gray-400 mb-1 block">CIDR</label>
                                                                        <input
                                                                            type="text"
                                                                            value={newFwAlias.cidr}
                                                                            onChange={e => setNewFwAlias(p => ({...p, cidr: e.target.value}))}
                                                                            placeholder="e.g. 10.0.0.1/32"
                                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                        />
                                                                    </div>
                                                                    <div>
                                                                        <label className="text-sm text-gray-400 mb-1 block">{t('comment')}</label>
                                                                        <input
                                                                            type="text"
                                                                            value={newFwAlias.comment}
                                                                            onChange={e => setNewFwAlias(p => ({...p, comment: e.target.value}))}
                                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                        />
                                                                    </div>
                                                                </div>
                                                                <div className="p-4 border-t border-proxmox-border flex gap-3 justify-end">
                                                                    <button onClick={() => setShowAddFwAlias(false)} className="px-4 py-2 bg-proxmox-dark rounded-lg hover:bg-proxmox-hover transition-colors">{t('cancel')}</button>
                                                                    <button
                                                                        onClick={async () => {
                                                                            if (!newFwAlias.name || !newFwAlias.cidr) return;
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/aliases`, {
                                                                                    method: 'POST',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify(newFwAlias)
                                                                                });
                                                                                if (res?.ok) {
                                                                                    fetchFirewallData();
                                                                                    setShowAddFwAlias(false);
                                                                                    setNewFwAlias({ name: '', cidr: '', comment: '' });
                                                                                }
                                                                            } catch (e) {}
                                                                        }}
                                                                        className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600 transition-colors"
                                                                    >
                                                                        {t('add')}
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Add IP Set Modal */}
                                                    {showAddFwIpset && (
                                                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 modal-backdrop" onClick={() => setShowAddFwIpset(false)}>
                                                            <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
                                                                <div className="p-4 border-b border-proxmox-border">
                                                                    <h3 className="font-semibold">{t('fwAddIpset') || 'Add IP Set'}</h3>
                                                                </div>
                                                                <div className="p-4 space-y-4">
                                                                    <div>
                                                                        <label className="text-sm text-gray-400 mb-1 block">{t('name')}</label>
                                                                        <input
                                                                            type="text"
                                                                            value={newFwIpset.name}
                                                                            onChange={e => setNewFwIpset(p => ({...p, name: e.target.value}))}
                                                                            placeholder="e.g. allowed-hosts"
                                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                        />
                                                                    </div>
                                                                    <div>
                                                                        <label className="text-sm text-gray-400 mb-1 block">{t('comment')}</label>
                                                                        <input
                                                                            type="text"
                                                                            value={newFwIpset.comment}
                                                                            onChange={e => setNewFwIpset(p => ({...p, comment: e.target.value}))}
                                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                                        />
                                                                    </div>
                                                                </div>
                                                                <div className="p-4 border-t border-proxmox-border flex gap-3 justify-end">
                                                                    <button onClick={() => setShowAddFwIpset(false)} className="px-4 py-2 bg-proxmox-dark rounded-lg hover:bg-proxmox-hover transition-colors">{t('cancel')}</button>
                                                                    <button
                                                                        onClick={async () => {
                                                                            if (!newFwIpset.name) return;
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/firewall/ipset`, {
                                                                                    method: 'POST',
                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                    body: JSON.stringify(newFwIpset)
                                                                                });
                                                                                if (res?.ok) {
                                                                                    fetchFirewallData();
                                                                                    setShowAddFwIpset(false);
                                                                                    setNewFwIpset({ name: '', comment: '' });
                                                                                }
                                                                            } catch (e) {}
                                                                        }}
                                                                        className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600 transition-colors"
                                                                    >
                                                                        {t('add')}
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    )}
                                                </>
                                            )}
                                        </div>
                                    )}

                                    {/* Options Tab */}
                                    {activeTab === 'options' && (
                                        <div className="space-y-6">
                                            <div className="space-y-4">
                                                {/* General Options Card */}
                                                <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border space-y-3">
                                                    <ConfigCheckboxField
                                                        label={t('startOnBoot')}
                                                        checked={getValue('options', 'onboot') == 1}
                                                        onChange={(v) => handleChange('options', 'onboot', v)}
                                                        t={t}
                                                    />
                                                    <ConfigCheckboxField
                                                        label={t('protection')}
                                                        checked={getValue('options', 'protection') == 1}
                                                        onChange={(v) => handleChange('options', 'protection', v)}
                                                        t={t}
                                                    />
                                                </div>
                                                {isQemu && (
                                                    <>
                                                        {/* QEMU Guest Agent Section */}
                                                        <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                            <div className="flex items-center justify-between mb-2">
                                                                <label className="flex items-center gap-2">
                                                                    <input 
                                                                        type="checkbox" 
                                                                        checked={getValue('options', 'agent')?.toString().includes('1')}
                                                                        onChange={(e) => {
                                                                            const current = getValue('options', 'agent') || '';
                                                                            if (e.target.checked) {
                                                                                handleChange('options', 'agent', '1');
                                                                            } else {
                                                                                handleChange('options', 'agent', '0');
                                                                            }
                                                                        }}
                                                                        className="w-4 h-4 rounded"
                                                                    />
                                                                    <span className="text-sm font-medium text-gray-300">{t('qemuGuestAgent')}</span>
                                                                    <span className="text-[10px] px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded font-medium">{t('needsRestart')}</span>
                                                                </label>
                                                            </div>
                                                            <p className="text-xs text-gray-500 mb-3">{t('qemuGuestAgentHint')}</p>
                                                            
                                                            {getValue('options', 'agent')?.toString().includes('1') && (
                                                                <div className="mt-3 pt-3 border-t border-proxmox-border space-y-2">
                                                                    <label className="flex items-center gap-2 text-sm text-gray-400">
                                                                        <input 
                                                                            type="checkbox"
                                                                            checked={getValue('options', 'agent')?.toString().includes('fstrim_cloned_disks=1')}
                                                                            onChange={(e) => {
                                                                                let agent = getValue('options', 'agent') || '1';
                                                                                if (e.target.checked) {
                                                                                    agent = agent.includes(',') ? agent + ',fstrim_cloned_disks=1' : '1,fstrim_cloned_disks=1';
                                                                                } else {
                                                                                    agent = agent.replace(/,?fstrim_cloned_disks=1/, '').replace(/^,/, '');
                                                                                }
                                                                                handleChange('options', 'agent', agent || '1');
                                                                            }}
                                                                            className="w-4 h-4 rounded"
                                                                        />
                                                                        {t('fstrim')}
                                                                    </label>
                                                                </div>
                                                            )}
                                                        </div>
                                                        
                                                        {/* Hotplug options */}
                                                        <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                            <label className="text-sm font-medium text-gray-300 block mb-2">{t('hotplug')}</label>
                                                            <p className="text-xs text-gray-500 mb-3">{t('hotplugHint')}</p>
                                                            <div className="flex flex-wrap gap-4">
                                                                {[
                                                                    { key: 'disk', label: t('hotplugDisk') },
                                                                    { key: 'network', label: t('hotplugNetwork') },
                                                                    { key: 'usb', label: t('hotplugUsb') },
                                                                    { key: 'memory', label: t('hotplugMemory') },
                                                                    { key: 'cpu', label: t('hotplugCpu') },
                                                                ].map(hp => {
                                                                    const hotplugValue = getValue('options', 'hotplug') || 'disk,network,usb';
                                                                    const isEnabled = hotplugValue === '1' || hotplugValue.includes(hp.key);
                                                                    return (
                                                                        <label key={hp.key} className="flex items-center gap-2 text-sm text-gray-400">
                                                                            <input 
                                                                                type="checkbox"
                                                                                checked={isEnabled}
                                                                                onChange={(e) => {
                                                                                    let current = getValue('options', 'hotplug') || 'disk,network,usb';
                                                                                    if (current === '1') current = 'disk,network,usb,memory,cpu';
                                                                                    if (current === '0') current = '';
                                                                                    
                                                                                    let parts = current.split(',').filter(p => p);
                                                                                    if (e.target.checked && !parts.includes(hp.key)) {
                                                                                        parts.push(hp.key);
                                                                                    } else if (!e.target.checked) {
                                                                                        parts = parts.filter(p => p !== hp.key);
                                                                                    }
                                                                                    handleChange('options', 'hotplug', parts.join(',') || '0');
                                                                                }}
                                                                                className="w-4 h-4 rounded"
                                                                            />
                                                                            {hp.label}
                                                                        </label>
                                                                    );
                                                                })}
                                                            </div>
                                                        </div>
                                                        
                                                        {/* Virtualization Options Card */}
                                                        <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border space-y-3">
                                                            <ConfigCheckboxField
                                                                label={t('kvmVirtualization')}
                                                                checked={getValue('options', 'kvm') == 1}
                                                                onChange={(v) => handleChange('options', 'kvm', v)}
                                                                needsRestart={true}
                                                                t={t}
                                                            />
                                                            <ConfigCheckboxField
                                                                label="ACPI"
                                                                checked={getValue('options', 'acpi') == 1}
                                                                onChange={(v) => handleChange('options', 'acpi', v)}
                                                                needsRestart={true}
                                                                t={t}
                                                            />
                                                        </div>
                                                    </>
                                                )}
                                                {!isQemu && (
                                                    <>
                                                        <ConfigCheckboxField
                                                            label={t('unprivilegedContainer')}
                                                            checked={getValue('options', 'unprivileged') == 1}
                                                            onChange={(v) => handleChange('options', 'unprivileged', v)}
                                                            disabled={true}
                                                            needsRestart={true}
                                                            t={t}
                                                        />
                                                    </>
                                                )}
                                            </div>
                                            {isQemu && (
                                                <div className="space-y-4">
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <ConfigInputField
                                                            label={t('osType')}
                                                            value={getValue('options', 'ostype')}
                                                            onChange={(v) => handleChange('options', 'ostype', v)}
                                                            options={[
                                                                { value: 'l26', label: 'Linux 2.6+' },
                                                                { value: 'l24', label: 'Linux 2.4' },
                                                                { value: 'win11', label: 'Windows 11' },
                                                                { value: 'win10', label: 'Windows 10' },
                                                                { value: 'win8', label: 'Windows 8' },
                                                                { value: 'win7', label: 'Windows 7' },
                                                                { value: 'wxp', label: 'Windows XP' },
                                                                { value: 'other', label: t('other') },
                                                            ]}
                                                        />
                                                    </div>
                                                    
                                                    {/* NS: Boot Order UI - Dec 2025 */}
                                                    <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                        <div className="flex items-center justify-between mb-3">
                                                            <label className="text-sm font-medium text-gray-300">{t('bootOrder') || 'Boot Order'}</label>
                                                            <span className="text-xs text-gray-500">{t('bootOrderHint') || 'Click to toggle, use arrows to reorder'}</span>
                                                        </div>
                                                        
                                                        {/* Parse current boot order and available devices */}
                                                        {(() => {
                                                            const currentBoot = getValue('options', 'boot') || '';
                                                            const bootDevices = currentBoot.includes('order=') 
                                                                ? currentBoot.split('order=')[1].split(';').filter(d => d)
                                                                : [];
                                                            
                                                            // LW: Collect all bootable devices from config
                                                            const allDevices = [];
                                                            if (config.disks) {
                                                                config.disks.forEach(d => {
                                                                    if (!d.id.includes('cloudinit')) allDevices.push(d.id);
                                                                });
                                                            }
                                                            if (config.networks) {
                                                                config.networks.forEach(n => allDevices.push(n.id));
                                                            }
                                                            // Add common devices that might not be in disks array
                                                            ['ide2', 'ide0', 'sata0', 'scsi0', 'virtio0', 'net0'].forEach(dev => {
                                                                if (!allDevices.includes(dev)) {
                                                                    // Check if device exists in raw config
                                                                    if (config[dev]) allDevices.push(dev);
                                                                }
                                                            });
                                                            
                                                            // Sort: boot devices first in order, then others
                                                            const sortedDevices = [
                                                                ...bootDevices.filter(d => allDevices.includes(d)),
                                                                ...allDevices.filter(d => !bootDevices.includes(d))
                                                            ].filter((v, i, a) => a.indexOf(v) === i); // unique
                                                            
                                                            const toggleDevice = (device) => {
                                                                const newOrder = bootDevices.includes(device)
                                                                    ? bootDevices.filter(d => d !== device)
                                                                    : [...bootDevices, device];
                                                                handleChange('options', 'boot', newOrder.length > 0 ? 'order=' + newOrder.join(';') : '');
                                                            };
                                                            
                                                            const moveDevice = (device, direction) => {
                                                                const idx = bootDevices.indexOf(device);
                                                                if (idx === -1) return;
                                                                const newOrder = [...bootDevices];
                                                                const newIdx = direction === 'up' ? idx - 1 : idx + 1;
                                                                if (newIdx < 0 || newIdx >= newOrder.length) return;
                                                                [newOrder[idx], newOrder[newIdx]] = [newOrder[newIdx], newOrder[idx]];
                                                                handleChange('options', 'boot', 'order=' + newOrder.join(';'));
                                                            };
                                                            
                                                            return (
                                                                <div className="space-y-1.5">
                                                                    {(() => {
                                                                        let enabledCounter = 0;
                                                                        return sortedDevices.map((device, idx) => {
                                                                        const isEnabled = bootDevices.includes(device);
                                                                        if (isEnabled) enabledCounter++;
                                                                        const displayNum = enabledCounter;
                                                                        const bootIdx = bootDevices.indexOf(device);
                                                                        const isFirst = bootIdx === 0;
                                                                        const isLast = bootIdx === bootDevices.length - 1;
                                                                        
                                                                        // NS: Determine device type icon + color
                                                                        const isDisk = device.match(/^(scsi|virtio|ide|sata)\d+$/);
                                                                        const isNet = device.match(/^net\d+$/);
                                                                        const isCdrom = device === 'ide2' || (config[device] && String(config[device]).includes('media=cdrom'));
                                                                        const iconColor = isCdrom ? 'text-yellow-400' : isNet ? 'text-cyan-400' : isDisk ? 'text-blue-400' : 'text-gray-400';
                                                                        const iconBg = isCdrom ? 'bg-yellow-500/10' : isNet ? 'bg-cyan-500/10' : isDisk ? 'bg-blue-500/10' : 'bg-gray-500/10';
                                                                        
                                                                        // Get device detail from config
                                                                        const deviceDetail = config[device] ? String(config[device]).split(',')[0] : '';
                                                                        
                                                                        return (
                                                                            <div 
                                                                                key={device}
                                                                                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all ${
                                                                                    isEnabled 
                                                                                        ? 'bg-gradient-to-r from-proxmox-orange/5 to-transparent border border-proxmox-orange/30' 
                                                                                        : 'bg-proxmox-darker/50 border border-transparent hover:border-proxmox-border'
                                                                                }`}
                                                                            >
                                                                                <input
                                                                                    type="checkbox"
                                                                                    checked={isEnabled}
                                                                                    onChange={() => toggleDevice(device)}
                                                                                    className="w-4 h-4 rounded border-gray-600 text-proxmox-orange focus:ring-proxmox-orange shrink-0"
                                                                                />
                                                                                <span className={`w-6 text-center text-xs font-bold shrink-0 ${isEnabled ? 'text-proxmox-orange' : 'text-gray-600'}`}>
                                                                                    {isEnabled ? `${displayNum}.` : '-'}
                                                                                </span>
                                                                                <div className={`p-1.5 rounded-md ${iconBg} shrink-0`}>
                                                                                    {isCdrom ? <Icons.Disc className={`w-4 h-4 ${iconColor}`} /> 
                                                                                     : isNet ? <Icons.Globe className={`w-4 h-4 ${iconColor}`} />
                                                                                     : isDisk ? <Icons.HardDrive className={`w-4 h-4 ${iconColor}`} />
                                                                                     : <Icons.Database className={`w-4 h-4 ${iconColor}`} />}
                                                                                </div>
                                                                                <div className="flex-1 min-w-0">
                                                                                    <span className={`font-mono text-sm ${isEnabled ? 'text-white font-medium' : 'text-gray-500'}`}>
                                                                                        {device}
                                                                                    </span>
                                                                                    {deviceDetail && (
                                                                                        <span className="ml-2 text-xs text-gray-500 truncate">{deviceDetail.length > 40 ? deviceDetail.substring(0,40) + '...' : deviceDetail}</span>
                                                                                    )}
                                                                                </div>
                                                                                {isEnabled && (
                                                                                    <div className="flex items-center gap-0.5 shrink-0">
                                                                                        <button
                                                                                            onClick={() => moveDevice(device, 'up')}
                                                                                            disabled={isFirst}
                                                                                            className="p-1.5 rounded-md hover:bg-white/5 disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
                                                                                            title="Move up"
                                                                                        >
                                                                                            <Icons.ChevronUp className="w-4 h-4" />
                                                                                        </button>
                                                                                        <button
                                                                                            onClick={() => moveDevice(device, 'down')}
                                                                                            disabled={isLast}
                                                                                            className="p-1.5 rounded-md hover:bg-white/5 disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
                                                                                            title="Move down"
                                                                                        >
                                                                                            <Icons.ChevronDown className="w-4 h-4" />
                                                                                        </button>
                                                                                    </div>
                                                                                )}
                                                                            </div>
                                                                        );
                                                                    });
                                                                    })()}
                                                                    {sortedDevices.length === 0 && (
                                                                        <div className="text-center py-4 text-gray-500 text-sm">
                                                                            {t('noBootDevices') || 'No boot devices found'}
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            );
                                                        })()}
                                                    </div>
                                                    
                                                    {/* SMBIOS Configuration */}
                                                    <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                        <div className="flex items-center justify-between mb-3">
                                                            <label className="text-sm font-medium text-gray-300 flex items-center gap-2">
                                                                <Icons.Cpu />
                                                                {t('smbiosSettings') || 'SMBIOS Settings'}
                                                            </label>
                                                            <span className="text-[10px] px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded font-medium">{t('needsRestart')}</span>
                                                        </div>
                                                        <p className="text-xs text-gray-500 mb-4">{t('smbiosHint') || 'System Management BIOS settings - useful for Windows licensing and VM identification'}</p>
                                                        
                                                        {/* Current SMBIOS value display */}
                                                        {getValue('options', 'smbios1') && (
                                                            <div className="mb-4 p-3 bg-black/50 rounded-lg border border-green-500/30">
                                                                <label className="block text-[10px] text-green-400 mb-1 font-medium">{t('currentValue') || 'Current Value'} (smbios1):</label>
                                                                <code className="text-xs text-green-300 font-mono break-all">
                                                                    {getValue('options', 'smbios1')}
                                                                </code>
                                                            </div>
                                                        )}
                                                        
                                                        {(() => {
                                                            // Parse existing smbios1 value
                                                            const smbiosRaw = getValue('options', 'smbios1') || '';
                                                            const parseSmbios = (raw) => {
                                                                const result = { uuid: '', manufacturer: '', product: '', version: '', serial: '', sku: '', family: '' };
                                                                if (!raw) return result;
                                                                raw.split(',').forEach(part => {
                                                                    const [key, ...valueParts] = part.split('=');
                                                                    const value = valueParts.join('='); // Handle values with = in them
                                                                    if (key && result.hasOwnProperty(key)) {
                                                                        result[key] = value || '';
                                                                    }
                                                                });
                                                                return result;
                                                            };
                                                            
                                                            const smbios = parseSmbios(smbiosRaw);
                                                            
                                                            // Sanitize for Proxmox SMBIOS - only A-Za-z0-9, learned the hard way that underscores dont work either
                                                            const sanitizeSmbios = (value) => {
                                                                if (!value) return '';
                                                                return value
                                                                    .replace(/\s+/g, '')  // Remove spaces
                                                                    .replace(/[^A-Za-z0-9]/g, '');  // Remove ALL other chars including underscores
                                                            };
                                                            
                                                            const buildSmbios = (newValues) => {
                                                                const parts = [];
                                                                Object.entries(newValues).forEach(([key, value]) => {
                                                                    if (value && value.trim()) {
                                                                        // UUID is special - don't sanitize
                                                                        const finalValue = key === 'uuid' ? value : sanitizeSmbios(value);
                                                                        if (finalValue) {
                                                                            parts.push(`${key}=${finalValue}`);
                                                                        }
                                                                    }
                                                                });
                                                                return parts.join(',');
                                                            };
                                                            
                                                            const updateSmbios = (field, value) => {
                                                                const newSmbios = { ...smbios, [field]: value };
                                                                const encoded = buildSmbios(newSmbios);
                                                                handleChange('options', 'smbios1', encoded || null);
                                                            };
                                                            
                                                            const generateUuid = () => {
                                                                return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
                                                                    const r = Math.random() * 16 | 0;
                                                                    const v = c === 'x' ? r : (r & 0x3 | 0x8);
                                                                    return v.toString(16);
                                                                });
                                                            };
                                                            
                                                            return (
                                                                <div className="space-y-3">
                                                                    {/* UUID - Display only, managed by Proxmox */}
                                                                    <div>
                                                                        <label className="block text-xs text-gray-400 mb-1">UUID <span className="text-gray-600">({t('managedByProxmox') || 'managed by Proxmox'})</span></label>
                                                                        <div className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-gray-500 text-sm font-mono">
                                                                            {smbios.uuid ? smbios.uuid : <span className="italic">{t('willBeAutoGenerated') || 'Will be auto-generated on save'}</span>}
                                                                        </div>
                                                                    </div>
                                                                    
                                                                    {/* Format hint */}
                                                                    <p className="text-[10px] text-yellow-500/70">
                                                                        ⚠️ {t('smbiosFormatHint') || 'Only letters and numbers allowed (A-Za-z0-9)'}
                                                                    </p>
                                                                    
                                                                    <div className="grid grid-cols-2 gap-3">
                                                                        {/* Manufacturer */}
                                                                        <div>
                                                                            <label className="block text-xs text-gray-400 mb-1">{t('manufacturer') || 'Manufacturer'}</label>
                                                                            <input
                                                                                type="text"
                                                                                value={smbios.manufacturer}
                                                                                onChange={(e) => updateSmbios('manufacturer', e.target.value)}
                                                                                placeholder="e.g. Dell"
                                                                                className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-white text-sm"
                                                                            />
                                                                            {smbios.manufacturer && sanitizeSmbios(smbios.manufacturer) !== smbios.manufacturer && (
                                                                                <p className="text-[10px] text-yellow-400 mt-0.5">↑ {sanitizeSmbios(smbios.manufacturer)}</p>
                                                                            )}
                                                                        </div>
                                                                        
                                                                        {/* Product */}
                                                                        <div>
                                                                            <label className="block text-xs text-gray-400 mb-1">{t('product') || 'Product'}</label>
                                                                            <input
                                                                                type="text"
                                                                                value={smbios.product}
                                                                                onChange={(e) => updateSmbios('product', e.target.value)}
                                                                                placeholder="e.g. PowerEdgeR740"
                                                                                className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-white text-sm"
                                                                            />
                                                                            {smbios.product && sanitizeSmbios(smbios.product) !== smbios.product && (
                                                                                <p className="text-[10px] text-yellow-400 mt-0.5">↑ {sanitizeSmbios(smbios.product)}</p>
                                                                            )}
                                                                        </div>
                                                                        
                                                                        {/* Version */}
                                                                        <div>
                                                                            <label className="block text-xs text-gray-400 mb-1">{t('version') || 'Version'}</label>
                                                                            <input
                                                                                type="text"
                                                                                value={smbios.version}
                                                                                onChange={(e) => updateSmbios('version', e.target.value)}
                                                                                placeholder="e.g. v1"
                                                                                className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-white text-sm"
                                                                            />
                                                                            {smbios.version && sanitizeSmbios(smbios.version) !== smbios.version && (
                                                                                <p className="text-[10px] text-yellow-400 mt-0.5">↑ {sanitizeSmbios(smbios.version)}</p>
                                                                            )}
                                                                        </div>
                                                                        
                                                                        {/* Serial */}
                                                                        <div>
                                                                            <label className="block text-xs text-gray-400 mb-1">{t('serialNumber') || 'Serial Number'}</label>
                                                                            <input
                                                                                type="text"
                                                                                value={smbios.serial}
                                                                                onChange={(e) => updateSmbios('serial', e.target.value)}
                                                                                placeholder="e.g. ABC123"
                                                                                className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-white text-sm"
                                                                            />
                                                                            {smbios.serial && sanitizeSmbios(smbios.serial) !== smbios.serial && (
                                                                                <p className="text-[10px] text-yellow-400 mt-0.5">↑ {sanitizeSmbios(smbios.serial)}</p>
                                                                            )}
                                                                        </div>
                                                                        
                                                                        {/* SKU */}
                                                                        <div>
                                                                            <label className="block text-xs text-gray-400 mb-1">SKU</label>
                                                                            <input
                                                                                type="text"
                                                                                value={smbios.sku}
                                                                                onChange={(e) => updateSmbios('sku', e.target.value)}
                                                                                placeholder="e.g. SKU12345"
                                                                                className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-white text-sm"
                                                                            />
                                                                            {smbios.sku && sanitizeSmbios(smbios.sku) !== smbios.sku && (
                                                                                <p className="text-[10px] text-yellow-400 mt-0.5">↑ {sanitizeSmbios(smbios.sku)}</p>
                                                                            )}
                                                                        </div>
                                                                        
                                                                        {/* Family */}
                                                                        <div>
                                                                            <label className="block text-xs text-gray-400 mb-1">{t('family') || 'Family'}</label>
                                                                            <input
                                                                                type="text"
                                                                                value={smbios.family}
                                                                                onChange={(e) => updateSmbios('family', e.target.value)}
                                                                                placeholder="e.g. Server"
                                                                                className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-white text-sm"
                                                                            />
                                                                            {smbios.family && sanitizeSmbios(smbios.family) !== smbios.family && (
                                                                                <p className="text-[10px] text-yellow-400 mt-0.5">↑ {sanitizeSmbios(smbios.family)}</p>
                                                                            )}
                                                                        </div>
                                                                    </div>
                                                                    
                                                                    {/* Live Preview */}
                                                                    {(smbios.uuid || smbios.manufacturer || smbios.product || smbios.version || smbios.serial || smbios.sku || smbios.family) && (
                                                                        <div className="p-3 bg-black/50 rounded-lg border border-proxmox-border">
                                                                            <label className="block text-[10px] text-gray-500 mb-1">{t('preview') || 'Preview'} (smbios1):</label>
                                                                            <code className="text-xs text-green-400 font-mono break-all">
                                                                                {buildSmbios(smbios)}
                                                                            </code>
                                                                        </div>
                                                                    )}
                                                                    
                                                                    {/* Quick presets - using only safe characters (A-Za-z0-9) */}
                                                                    <div className="pt-2 border-t border-proxmox-border">
                                                                        <label className="block text-xs text-gray-400 mb-2">{t('presets') || 'Quick Presets'}</label>
                                                                        <div className="flex flex-wrap gap-2">
                                                                            <button
                                                                                onClick={() => {
                                                                                    const base = smbios.uuid ? `uuid=${smbios.uuid},` : '';
                                                                                    handleChange('options', 'smbios1', `${base}manufacturer=Dell,product=PowerEdgeR740,version=v1,serial=DELL${Math.random().toString(36).substr(2, 8).toUpperCase()},family=Server`);
                                                                                }}
                                                                                className="px-2 py-1 bg-proxmox-card border border-proxmox-border rounded text-xs text-gray-400 hover:text-white hover:bg-proxmox-border"
                                                                            >
                                                                                Dell Server
                                                                            </button>
                                                                            <button
                                                                                onClick={() => {
                                                                                    const base = smbios.uuid ? `uuid=${smbios.uuid},` : '';
                                                                                    handleChange('options', 'smbios1', `${base}manufacturer=HP,product=ProLiantDL380,version=v1,serial=MXQ${Math.random().toString(36).substr(2, 8).toUpperCase()},family=Server`);
                                                                                }}
                                                                                className="px-2 py-1 bg-proxmox-card border border-proxmox-border rounded text-xs text-gray-400 hover:text-white hover:bg-proxmox-border"
                                                                            >
                                                                                HP Server
                                                                            </button>
                                                                            <button
                                                                                onClick={() => {
                                                                                    const base = smbios.uuid ? `uuid=${smbios.uuid},` : '';
                                                                                    handleChange('options', 'smbios1', `${base}manufacturer=Lenovo,product=ThinkPadX1,version=v1,serial=PF${Math.random().toString(36).substr(2, 8).toUpperCase()},family=ThinkPad`);
                                                                                }}
                                                                                className="px-2 py-1 bg-proxmox-card border border-proxmox-border rounded text-xs text-gray-400 hover:text-white hover:bg-proxmox-border"
                                                                            >
                                                                                Lenovo Laptop
                                                                            </button>
                                                                            <button
                                                                                onClick={async () => {
                                                                                    // NS: fetch smbios settings from cluster config
                                                                                    const sanitize = (v) => (v || '').replace(/\s+/g, '').replace(/[^A-Za-z0-9]/g, '');
                                                                                    try {
                                                                                        const res = await authFetch(`${API_URL}/clusters/${clusterId}/smbios-autoconfig`);
                                                                                        const settings = res?.ok ? await res.json() : {};
                                                                                        const mfg = sanitize(settings.manufacturer) || 'Proxmox';
                                                                                        const prod = sanitize(settings.product) || 'PegaProxManagment';
                                                                                        const ver = sanitize(settings.version) || 'v1';
                                                                                        const fam = sanitize(settings.family) || 'ProxmoxVE';
                                                                                        const timestamp = new Date().toISOString().replace(/[-:T.Z]/g, '').slice(2, 14);
                                                                                        const randomPart = Math.floor(Math.random() * 9000 + 1000);
                                                                                        const base = smbios.uuid ? `uuid=${smbios.uuid},` : '';
                                                                                        handleChange('options', 'smbios1', `${base}manufacturer=${mfg},product=${prod},version=${ver},serial=PVE${timestamp}${randomPart},family=${fam}`);
                                                                                    } catch (e) {
                                                                                        // fallback to defaults
                                                                                        const base = smbios.uuid ? `uuid=${smbios.uuid},` : '';
                                                                                        const timestamp = new Date().toISOString().replace(/[-:T.Z]/g, '').slice(2, 14);
                                                                                        const randomPart = Math.floor(Math.random() * 9000 + 1000);
                                                                                        handleChange('options', 'smbios1', `${base}manufacturer=Proxmox,product=PegaProxManagment,version=v1,serial=PVE${timestamp}${randomPart},family=ProxmoxVE`);
                                                                                    }
                                                                                }}
                                                                                className="px-2 py-1 bg-proxmox-orange/20 border border-proxmox-orange/50 rounded text-xs text-proxmox-orange hover:bg-proxmox-orange/30"
                                                                                title={t('applySmbiosFromClusterConfig') || 'Apply SMBIOS settings from cluster configuration'}
                                                                            >
                                                                                🦄 PegaProx
                                                                            </button>
                                                                            <button
                                                                                onClick={() => {
                                                                                    const base = smbios.uuid ? `uuid=${smbios.uuid},` : '';
                                                                                    handleChange('options', 'smbios1', `${base}manufacturer=Microsoft,product=VirtualMachine,version=HyperV,serial=0000000000000000,family=VirtualMachine`);
                                                                                }}
                                                                                className="px-2 py-1 bg-proxmox-card border border-proxmox-border rounded text-xs text-gray-400 hover:text-white hover:bg-proxmox-border"
                                                                            >
                                                                                Hyper-V
                                                                            </button>
                                                                            <button
                                                                                onClick={() => {
                                                                                    handleChange('options', 'smbios1', '');
                                                                                }}
                                                                                className="px-2 py-1 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400 hover:bg-red-500/20"
                                                                            >
                                                                                {t('clear') || 'Clear'}
                                                                            </button>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            );
                                                        })()}
                                                    </div>
                                                </div>
                                            )}
                                            {!isQemu && (
                                                <div className="grid grid-cols-2 gap-4">
                                                    <ConfigInputField
                                                        label="Nameserver"
                                                        value={getValue('options', 'nameserver')}
                                                        onChange={(v) => handleChange('options', 'nameserver', v)}
                                                    />
                                                    <ConfigInputField
                                                        label="Search Domain"
                                                        value={getValue('options', 'searchdomain')}
                                                        onChange={(v) => handleChange('options', 'searchdomain', v)}
                                                    />
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </>
                            ) : (
                                <div className="text-center py-8 text-red-400">
                                    Konfiguration konnte nicht geladen werden
                                </div>
                            )}
                        </div>

                        {/* Footer */}
                        <div className="flex items-center justify-between px-6 py-4 border-t border-proxmox-border bg-proxmox-dark">
                            <div className="text-xs text-gray-500">
                                {vm.status === 'running' && (
                                    <span className="text-yellow-400">
                                        {t('changesRequireRestart')}
                                    </span>
                                )}
                            </div>
                            <div className="flex items-center gap-3">
                                <button
                                    onClick={onClose}
                                    className="px-4 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-300 font-medium hover:bg-proxmox-hover transition-colors"
                                >
                                    {t('cancel')}
                                </button>
                                <button
                                    onClick={handleSave}
                                    disabled={!hasChanges || saving}
                                    className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange rounded-lg text-white font-medium hover:bg-orange-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    {saving ? (
                                        <Icons.RotateCw />
                                    ) : (
                                        <Icons.Save />
                                    )}
                                    {t('save')}
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* Sub-Modals */}
                    {showAddDisk && (
                        <AddDiskModal
                            isQemu={isQemu}
                            storageList={storageList}
                            hardwareOptions={hardwareOptions}
                            getNextDiskId={getNextDiskId}
                            onAdd={handleAddDisk}
                            onClose={() => setShowAddDisk(false)}
                        />
                    )}

                    {showResizeDisk && (
                        <ResizeDiskModal
                            disk={showResizeDisk}
                            onResize={(size) => handleResizeDisk(showResizeDisk.id, size)}
                            onClose={() => setShowResizeDisk(null)}
                        />
                    )}

                    {showMoveDisk && (
                        <MoveDiskModal
                            disk={showMoveDisk}
                            storageList={storageList}
                            onMove={(storage, deleteSource) => handleMoveDisk(showMoveDisk.id, storage, deleteSource)}
                            onClose={() => setShowMoveDisk(null)}
                        />
                    )}

                    {/* MK: Edit Disk Bus Type Modal */}
                    {showEditDisk && (
                        <EditDiskBusModal
                            disk={showEditDisk}
                            hardwareOptions={hardwareOptions}
                            vmStatus={config?.status?.status}
                            onSave={async (newBusType) => {
                                // MK: Double-check VM is stopped before changing bus type
                                if (config?.status?.status === 'running') {
                                    addToast(t('vmMustBeStopped') || 'VM must be stopped to change disk bus type', 'error');
                                    return;
                                }
                                
                                const oldId = showEditDisk.id;
                                const oldBusMatch = oldId.match(/^([a-z]+)(\d+)$/);
                                if (!oldBusMatch) {
                                    addToast('Invalid disk ID format', 'error');
                                    return;
                                }
                                const oldBus = oldBusMatch[1];
                                const oldNum = oldBusMatch[2];
                                
                                // Find next available ID for new bus type
                                const existingIds = (config?.disks || []).map(d => d.id);
                                let newNum = 0;
                                while (existingIds.includes(`${newBusType}${newNum}`)) {
                                    newNum++;
                                }
                                const newId = `${newBusType}${newNum}`;
                                
                                if (oldId === newId) {
                                    setShowEditDisk(null);
                                    return;
                                }
                                
                                try {
                                    // LW: Get current disk value and clean it for new bus type
                                    let currentValue = config?.raw?.[oldId] || showEditDisk.volume;
                                    
                                    // MK: Strip unsupported options based on target bus type
                                    // iothread only supported on scsi/virtio
                                    if (!['scsi', 'virtio'].includes(newBusType)) {
                                        currentValue = currentValue.replace(/,iothread=\d+/g, '');
                                    }
                                    // ssd only supported on scsi/virtio/sata (not ide)
                                    if (!['scsi', 'virtio', 'sata'].includes(newBusType)) {
                                        currentValue = currentValue.replace(/,ssd=\d+/g, '');
                                    }
                                    
                                    // MK: IMPORTANT - Remove size= parameter! 
                                    // If size is present, Proxmox thinks we want to CREATE a new disk
                                    // For reattaching existing volumes, size must be omitted
                                    currentValue = currentValue.replace(/,size=\d+[KMGT]?/gi, '');
                                    
                                    // LW: Two-step process to avoid creating new volume:
                                    // Delete old disk config (volume becomes "unused")
                                    const deleteRes = await fetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`, {
                                        method: 'PUT',
                                        credentials: 'include',
                                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ delete: oldId })
                                    });
                                    
                                    if (!deleteRes.ok) {
                                        const err = await deleteRes.json();
                                        addToast(err.error || 'Error detaching old disk', 'error');
                                        return;
                                    }
                                    
                                    // MK: Small delay to let Proxmox process the detach
                                    await new Promise(r => setTimeout(r, 500));
                                    
                                    // Attach volume with new bus type
                                    const attachRes = await fetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`, {
                                        method: 'PUT',
                                        credentials: 'include',
                                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ [newId]: currentValue })
                                    });
                                    
                                    if (attachRes.ok) {
                                        addToast(`${t('diskBusChanged') || 'Disk bus changed'}: ${oldId} ↑ ${newId}`, 'success');
                                        fetchConfig();
                                        setShowEditDisk(null);
                                    } else {
                                        const err = await attachRes.json();
                                        addToast(err.error || 'Error attaching disk with new bus type', 'error');
                                        // LW: Try to restore old config on failure
                                        await fetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`, {
                                            method: 'PUT',
                                            credentials: 'include',
                                            headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                            body: JSON.stringify({ [oldId]: config?.raw?.[oldId] || showEditDisk.volume })
                                        });
                                        fetchConfig();
                                    }
                                } catch (e) {
                                    addToast('Error changing disk bus', 'error');
                                }
                            }}
                            onClose={() => setShowEditDisk(null)}
                        />
                    )}

                    {/* MK: Reattach unused disk modal */}
                    {showReattachDisk && (
                        <ReattachDiskModal
                            disk={showReattachDisk}
                            getNextDiskId={getNextDiskId}
                            onReattach={async (diskId, diskValue) => {
                                try {
                                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`, {
                                        method: 'PUT',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ [diskId]: diskValue })
                                    });
                                    if (res && res.ok) {
                                        addToast(`${t('diskReattached') || 'Disk reattached as'} ${diskId}`, 'success');
                                        fetchConfig();
                                        setShowReattachDisk(null);
                                    } else {
                                        const err = await res.json();
                                        addToast(err.error || 'Error reattaching disk', 'error');
                                    }
                                } catch (e) {
                                    addToast('Error reattaching disk', 'error');
                                }
                            }}
                            onClose={() => setShowReattachDisk(null)}
                        />
                    )}

                    {/* MK: Import Disk Modal */}
                    {showImportDisk && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-lg bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                <h3 className="text-lg font-semibold text-white mb-2">{t('importDisk') || 'Import Disk'}</h3>
                                <p className="text-sm text-gray-400 mb-4">{t('importDiskDesc') || 'Import existing disk image from storage'}</p>
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('selectImportStorage') || 'Source Storage'}</label>
                                        <select
                                            id="importStorage"
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white"
                                            onChange={async (e) => {
                                                const storage = e.target.value;
                                                if (!storage) { setImportableDisks([]); return; }
                                                try {
                                                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${vm.node}/storage/${storage}/content?content=images`);
                                                    if (res && res.ok) {
                                                        const data = await res.json();
                                                        // Filter for disk images that could be imported
                                                        const disks = (data || []).filter(item => 
                                                            item.format && ['raw', 'qcow2', 'vmdk'].includes(item.format)
                                                        );
                                                        setImportableDisks(disks);
                                                    }
                                                } catch(e) { setImportableDisks([]); }
                                            }}
                                        >
                                            <option value="">-- {t('selectStorage') || 'Select Storage'} --</option>
                                            {storageList.filter(s => s.type !== 'iso' && s.type !== 'vztmpl').map(s => (
                                                <option key={s.storage} value={s.storage}>{s.storage} ({s.type})</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('selectDiskImage') || 'Select Disk Image'}</label>
                                        <select
                                            id="importDiskImage"
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white"
                                        >
                                            <option value="">-- {t('selectDiskImage') || 'Select Image'} --</option>
                                            {importableDisks.map(disk => (
                                                <option key={disk.volid} value={disk.volid}>
                                                    {disk.volid} ({disk.format}, {Math.round((disk.size || 0) / 1024 / 1024 / 1024)} GB)
                                                </option>
                                            ))}
                                        </select>
                                        {importableDisks.length === 0 && (
                                            <p className="text-xs text-yellow-500 mt-1">{t('noImportableDisks') || 'No importable disk images found'}</p>
                                        )}
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('targetBus') || 'Target Bus'}</label>
                                        <select
                                            id="importTargetBus"
                                            defaultValue="scsi"
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white"
                                        >
                                            <option value="scsi">SCSI</option>
                                            <option value="virtio">VirtIO</option>
                                            <option value="sata">SATA</option>
                                            <option value="ide">IDE</option>
                                        </select>
                                    </div>
                                    <div className="flex gap-2 justify-end pt-4">
                                        <button onClick={() => { setShowImportDisk(false); setImportableDisks([]); }} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded text-gray-300">{t('cancel')}</button>
                                        <button 
                                            onClick={async () => {
                                                const volid = document.getElementById('importDiskImage').value;
                                                const sourceStorage = document.getElementById('importStorage').value;
                                                const targetBus = document.getElementById('importTargetBus').value;
                                                if (!volid) { addToast('Please select a disk image', 'error'); return; }
                                                
                                                // MK: Ensure volid has storage prefix (some APIs return just volume name)
                                                let fullVolid = volid;
                                                if (!volid.includes(':') && sourceStorage) {
                                                    fullVolid = `${sourceStorage}:${volid}`;
                                                }
                                                
                                                // Get next available disk ID for the bus type
                                                const nextId = getNextDiskId(targetBus);
                                                
                                                try {
                                                    // Import by setting the disk config
                                                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`, {
                                                        method: 'PUT',
                                                        headers: { 'Content-Type': 'application/json' },
                                                        body: JSON.stringify({ [nextId]: fullVolid })
                                                    });
                                                    if (res && res.ok) {
                                                        addToast(t('diskImported') || 'Disk imported', 'success');
                                                        await new Promise(resolve => setTimeout(resolve, 500));
                                                        fetchConfig();
                                                        setShowImportDisk(false);
                                                        setImportableDisks([]);
                                                    } else {
                                                        const err = await res.json();
                                                        addToast(err.error || 'Error importing disk', 'error');
                                                    }
                                                } catch(e) {
                                                    addToast('Error importing disk', 'error');
                                                }
                                            }}
                                            className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded text-white"
                                        >
                                            {t('import') || 'Import'}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* MK: Reassign Owner Modal */}
                    {showReassignOwner && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-lg bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                <h3 className="text-lg font-semibold text-white mb-2">{t('reassignOwner') || 'Reassign Owner'}</h3>
                                <p className="text-sm text-gray-400 mb-4">{t('reassignOwnerDesc') || 'Assign disk to a different VM'}</p>
                                <div className="space-y-4">
                                    <div className="p-3 bg-proxmox-dark rounded">
                                        <span className="text-gray-400">{t('disk') || 'Disk'}:</span>
                                        <span className="ml-2 text-white font-mono">{showReassignOwner.id}</span>
                                        <span className="ml-2 text-gray-500">({showReassignOwner.volume})</span>
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('targetVm') || 'Target VM'}</label>
                                        <select
                                            id="reassignTargetVm"
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white"
                                        >
                                            <option value="">-- {t('selectVm') || 'Select VM'} --</option>
                                            {(window.pegaproxVmList || []).filter(v => v.type === 'qemu' && v.vmid !== vm.vmid).map(v => (
                                                <option key={v.vmid} value={v.vmid}>{v.vmid} - {v.name}</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('targetBus') || 'Target Bus'}</label>
                                        <select
                                            id="reassignTargetBus"
                                            defaultValue="scsi"
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white"
                                        >
                                            <option value="scsi">SCSI</option>
                                            <option value="virtio">VirtIO</option>
                                            <option value="sata">SATA</option>
                                        </select>
                                    </div>
                                    <div className="flex gap-2 justify-end pt-4">
                                        <button onClick={() => setShowReassignOwner(null)} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded text-gray-300">{t('cancel')}</button>
                                        <button 
                                            onClick={async () => {
                                                const targetVmid = document.getElementById('reassignTargetVm').value;
                                                const targetBus = document.getElementById('reassignTargetBus').value;
                                                if (!targetVmid) { addToast('Please select a target VM', 'error'); return; }
                                                
                                                try {
                                                    // Detach from current VM
                                                    const detachRes = await authFetch(
                                                        `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/disks/${showReassignOwner.id}`,
                                                        { method: 'DELETE' }
                                                    );
                                                    if (!detachRes || !detachRes.ok) {
                                                        const err = await detachRes.json();
                                                        addToast(err.error || 'Error detaching disk', 'error');
                                                        return;
                                                    }
                                                    
                                                    // Attach to target VM
                                                    // Need to get the next available disk ID for target VM
                                                    const configRes = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/qemu/${targetVmid}/config`);
                                                    let nextId = `${targetBus}0`;
                                                    if (configRes && configRes.ok) {
                                                        const targetConfig = await configRes.json();
                                                        // Find next available ID
                                                        for (let i = 0; i < 30; i++) {
                                                            const testId = `${targetBus}${i}`;
                                                            if (!targetConfig[testId]) {
                                                                nextId = testId;
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    
                                                    // MK: Use full volume path (storage:volume) - disk.value has the complete string
                                                    // But we need to strip any extra options like ,size=32G
                                                    let volumePath = showReassignOwner.value || `${showReassignOwner.storage}:${showReassignOwner.volume}`;
                                                    // Extract just the storage:volume part (before any comma)
                                                    volumePath = volumePath.split(',')[0];
                                                    
                                                    const attachRes = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/qemu/${targetVmid}/config`, {
                                                        method: 'PUT',
                                                        headers: { 'Content-Type': 'application/json' },
                                                        body: JSON.stringify({ [nextId]: volumePath })
                                                    });
                                                    
                                                    if (attachRes && attachRes.ok) {
                                                        addToast(t('diskReassigned') || 'Disk reassigned', 'success');
                                                        await new Promise(resolve => setTimeout(resolve, 500));
                                                        fetchConfig();
                                                        setShowReassignOwner(null);
                                                    } else {
                                                        const err = await attachRes.json();
                                                        addToast(err.error || 'Error attaching to target VM', 'error');
                                                    }
                                                } catch(e) {
                                                    addToast('Error reassigning disk', 'error');
                                                }
                                            }}
                                            className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded text-white"
                                        >
                                            {t('reassign') || 'Reassign'}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {showMountISO && (
                        <MountISOModal
                            isoList={isoList}
                            existingDrives={
                                // Extract existing drives from config.disks array
                                (config?.disks || []).map(disk => ({
                                    key: disk.id,
                                    isCdrom: String(disk.value || '').includes('media=cdrom')
                                }))
                            }
                            onMount={handleMountISO}
                            onClose={() => setShowMountISO(false)}
                        />
                    )}

                    {showAddNetwork && (
                        <AddNetworkModal
                            isQemu={isQemu}
                            bridgeList={bridgeList}
                            hardwareOptions={hardwareOptions}
                            getNextNetId={getNextNetId}
                            generateMAC={generateMAC}
                            onAdd={handleAddNetwork}
                            onClose={() => setShowAddNetwork(false)}
                        />
                    )}

                    {showEditNetwork && (
                        <EditNetworkModal
                            isQemu={isQemu}
                            network={showEditNetwork}
                            bridgeList={bridgeList}
                            hardwareOptions={hardwareOptions}
                            generateMAC={generateMAC}
                            onUpdate={(config) => handleUpdateNetwork(showEditNetwork.id, config)}
                            onClose={() => setShowEditNetwork(null)}
                        />
                    )}

                    {/* Add PCI Device Modal */}
                    {showAddPci && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-lg bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                <h3 className="text-lg font-semibold text-white mb-4">{t('addPci')}</h3>
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('availableDevices')}</label>
                                        <select
                                            value={selectedPciDevice?.id || ''}
                                            onChange={(e) => setSelectedPciDevice(availablePci.find(d => d.id === e.target.value))}
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white"
                                        >
                                            <option value="">-- {t('selectDevice')} --</option>
                                            {availablePci.filter(d => d.iommugroup >= 0).map(dev => (
                                                <option key={dev.id} value={dev.id}>
                                                    {dev.id} - {dev.vendor_name} {dev.device_name} (IOMMU: {dev.iommugroup})
                                                </option>
                                            ))}
                                        </select>
                                    </div>
                                    {selectedPciDevice && (
                                        <div className="p-3 bg-proxmox-dark rounded text-sm">
                                            <div className="text-gray-400">{t('vendor')}: <span className="text-white">{selectedPciDevice.vendor_name}</span></div>
                                            <div className="text-gray-400">Device: <span className="text-white">{selectedPciDevice.device_name}</span></div>
                                            <div className="text-gray-400">{t('iommuGroup')}: <span className="text-white">{selectedPciDevice.iommugroup}</span></div>
                                        </div>
                                    )}
                                    <div className="space-y-2">
                                        <label className="flex items-center gap-2">
                                            <input type="checkbox" checked={pciOptions.pcie} onChange={(e) => setPciOptions({...pciOptions, pcie: e.target.checked})} className="rounded" />
                                            <span className="text-sm text-gray-300">{t('pcie')}</span>
                                        </label>
                                        <label className="flex items-center gap-2">
                                            <input type="checkbox" checked={pciOptions.rombar} onChange={(e) => setPciOptions({...pciOptions, rombar: e.target.checked})} className="rounded" />
                                            <span className="text-sm text-gray-300">{t('romBar')}</span>
                                        </label>
                                    </div>
                                    <div className="flex gap-2 justify-end pt-4">
                                        <button onClick={() => { setShowAddPci(false); setSelectedPciDevice(null); }} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded">{t('cancel')}</button>
                                        <button onClick={handleAddPciDevice} disabled={!selectedPciDevice || passthroughLoading} className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded disabled:opacity-50">
                                            {passthroughLoading ? t('adding') : t('add')}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Add USB Device Modal */}
                    {showAddUsb && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-lg bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                <h3 className="text-lg font-semibold text-white mb-4">{t('addUsb')}</h3>
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('availableDevices')}</label>
                                        <select
                                            value={selectedUsbDevice ? `${selectedUsbDevice.vendid}:${selectedUsbDevice.prodid}` : ''}
                                            onChange={(e) => {
                                                const [vid, pid] = e.target.value.split(':');
                                                setSelectedUsbDevice(availableUsb.find(d => d.vendid === vid && d.prodid === pid));
                                            }}
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white"
                                        >
                                            <option value="">-- {t('selectDevice')} --</option>
                                            {availableUsb.map((dev, idx) => (
                                                <option key={idx} value={`${dev.vendid}:${dev.prodid}`}>
                                                    {dev.manufacturer || dev.vendid} - {dev.product || dev.prodid}
                                                </option>
                                            ))}
                                        </select>
                                    </div>
                                    <label className="flex items-center gap-2">
                                        <input type="checkbox" checked={usbOptions.usb3} onChange={(e) => setUsbOptions({...usbOptions, usb3: e.target.checked})} className="rounded" />
                                        <span className="text-sm text-gray-300">{t('usb3')}</span>
                                    </label>
                                    <div className="flex gap-2 justify-end pt-4">
                                        <button onClick={() => { setShowAddUsb(false); setSelectedUsbDevice(null); }} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded">{t('cancel')}</button>
                                        <button onClick={handleAddUsbDevice} disabled={!selectedUsbDevice || passthroughLoading} className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded disabled:opacity-50">
                                            {passthroughLoading ? t('adding') : t('add')}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Add Serial Port Modal */}
                    {showAddSerial && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                <h3 className="text-lg font-semibold text-white mb-4">{t('addSerial')}</h3>
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('serialType')}</label>
                                        <select
                                            value={serialType}
                                            onChange={(e) => setSerialType(e.target.value)}
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white"
                                        >
                                            <option value="socket">{t('socketConsole')}</option>
                                            <option value="/dev/ttyUSB0">/dev/ttyUSB0</option>
                                            <option value="/dev/ttyUSB1">/dev/ttyUSB1</option>
                                            <option value="/dev/ttyS0">/dev/ttyS0</option>
                                            <option value="/dev/ttyS1">/dev/ttyS1</option>
                                        </select>
                                    </div>
                                    <div className="flex gap-2 justify-end pt-4">
                                        <button onClick={() => setShowAddSerial(false)} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded">{t('cancel')}</button>
                                        <button onClick={handleAddSerialPort} disabled={passthroughLoading} className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded disabled:opacity-50">
                                            {passthroughLoading ? t('adding') : t('add')}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* MK: Add EFI Disk Modal - Jan 2026
                        LW: Size is always 4MB, pre-enrolled keys for Secure Boot */}
                    {showAddEfiDisk && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                    <Icons.HardDrive className="text-blue-400" />
                                    {t('addEfiDisk') || 'Add EFI Disk'}
                                </h3>
                                <div className="space-y-4">
                                    <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg text-sm text-blue-300">
                                        {t('efiDiskInfo') || 'EFI disk stores UEFI firmware variables and is required for UEFI boot. Size is automatically set to 4MB.'}
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('storage') || 'Storage'}</label>
                                        <select
                                            value={efiStorage}
                                            onChange={(e) => setEfiStorage(e.target.value)}
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white"
                                        >
                                            <option value="">{t('selectStorage') || 'Select storage...'}</option>
                                            {storageList.filter(s => s.content?.includes('images')).map(s => (
                                                <option key={s.storage} value={s.storage}>{s.storage}</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div className="flex gap-2 justify-end pt-4">
                                        <button onClick={() => setShowAddEfiDisk(false)} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded">{t('cancel')}</button>
                                        <button 
                                            onClick={async () => {
                                                if (!efiStorage) return;
                                                setPassthroughLoading(true);
                                                try {
                                                    const res = await fetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`, {
                                                        method: 'PUT',
                                                        credentials: 'include',
                                                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                                        body: JSON.stringify({ efidisk0: `${efiStorage}:1,efitype=4m,pre-enrolled-keys=1` })
                                                    });
                                                    if (res.ok) {
                                                        addToast(t('efiDiskAdded') || 'EFI disk added', 'success');
                                                        setShowAddEfiDisk(false);
                                                        fetchConfig();
                                                    } else {
                                                        const err = await res.json();
                                                        addToast(err.error || 'Error adding EFI disk', 'error');
                                                    }
                                                } catch (e) {
                                                    addToast('Error adding EFI disk', 'error');
                                                }
                                                setPassthroughLoading(false);
                                            }}
                                            disabled={!efiStorage || passthroughLoading} 
                                            className="px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded disabled:opacity-50"
                                        >
                                            {passthroughLoading ? t('adding') : t('add')}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* MK: Add TPM Modal */}
                    {showAddTpm && (
                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                            <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                    <Icons.Shield className="text-green-400" />
                                    {t('addTpm') || 'Add TPM'}
                                </h3>
                                <div className="space-y-4">
                                    <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-sm text-yellow-300">
                                        <div className="flex items-start gap-2">
                                            <Icons.AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                                            <div>{t('tpmInfo') || 'TPM (Trusted Platform Module) is required for Windows 11 and provides hardware-based security features like BitLocker.'}</div>
                                        </div>
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('storage') || 'Storage'}</label>
                                        <select
                                            value={tpmStorage}
                                            onChange={(e) => setTpmStorage(e.target.value)}
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white"
                                        >
                                            <option value="">{t('selectStorage') || 'Select storage...'}</option>
                                            {storageList.filter(s => s.content?.includes('images')).map(s => (
                                                <option key={s.storage} value={s.storage}>{s.storage}</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">{t('tpmVersion') || 'TPM Version'}</label>
                                        <select
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white"
                                            defaultValue="v2.0"
                                        >
                                            <option value="v2.0">TPM 2.0 ({t('recommended') || 'Recommended'})</option>
                                            <option value="v1.2">TPM 1.2</option>
                                        </select>
                                    </div>
                                    <div className="flex gap-2 justify-end pt-4">
                                        <button onClick={() => setShowAddTpm(false)} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded">{t('cancel')}</button>
                                        <button 
                                            onClick={async () => {
                                                if (!tpmStorage) return;
                                                setPassthroughLoading(true);
                                                try {
                                                    const res = await fetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/config`, {
                                                        method: 'PUT',
                                                        credentials: 'include',
                                                        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                                                        body: JSON.stringify({ tpmstate0: `${tpmStorage}:1,version=v2.0` })
                                                    });
                                                    if (res.ok) {
                                                        addToast(t('tpmAdded') || 'TPM added', 'success');
                                                        setShowAddTpm(false);
                                                        fetchConfig();
                                                    } else {
                                                        const err = await res.json();
                                                        addToast(err.error || 'Error adding TPM', 'error');
                                                    }
                                                } catch (e) {
                                                    addToast('Error adding TPM', 'error');
                                                }
                                                setPassthroughLoading(false);
                                            }}
                                            disabled={!tpmStorage || passthroughLoading} 
                                            className="px-4 py-2 bg-green-500 hover:bg-green-600 rounded disabled:opacity-50"
                                        >
                                            {passthroughLoading ? t('adding') : t('add')}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            );
        }

        // Sub-modals for disk/network operations
        // LW: Disk creation modal - handles both QEMU and LXC
        // TODO(LW): Maybe add RAID level selection for ZFS pools?
        function AddDiskModal({ isQemu, storageList, hardwareOptions, getNextDiskId, onAdd, onClose }) {
            const { t } = useTranslation();
            const [diskConfig, setDiskConfig] = useState({
                disk_id: 'scsi1',
                storage: storageList[0]?.storage || 'local-lvm',
                size: 32,
                cache: '',
                iothread: true,
                ssd: false,
                discard: true,
            });
            
            // MK: Get current bus type from disk_id (e.g. "scsi0" -> "scsi")
            const currentBus = diskConfig.disk_id.replace(/[0-9]/g, '');
            // LW: iothread needs virtio-scsi-pci controller, won't work with IDE/SATA
            const supportsIothread = ['scsi', 'virtio'].includes(currentBus);
            // MK: ssd emulation for TRIM support - IDE doesn't support it at all
            const supportsSsd = ['scsi', 'virtio', 'sata'].includes(currentBus);

            useEffect(() => {
                if (getNextDiskId) {
                    setDiskConfig(prev => ({...prev, disk_id: getNextDiskId('scsi')}));
                }
            }, []);
            
            // NS: Handle bus type change - reset unsupported options
            const handleBusChange = (newBus) => {
                const newId = getNextDiskId ? getNextDiskId(newBus) : newBus + '0';
                const busSupportsIothread = ['scsi', 'virtio'].includes(newBus);
                const busSupportsSsd = ['scsi', 'virtio', 'sata'].includes(newBus);
                setDiskConfig({
                    ...diskConfig, 
                    disk_id: newId,
                    iothread: busSupportsIothread ? diskConfig.iothread : false,
                    ssd: busSupportsSsd ? diskConfig.ssd : false
                });
            };
            
            // NS: Filter out unsupported options before sending to API
            const handleAdd = () => {
                const configToSend = { 
                    disk_id: diskConfig.disk_id,
                    storage: diskConfig.storage,
                    size: diskConfig.size,
                    discard: diskConfig.discard
                };
                // Only add cache if set
                if (diskConfig.cache) {
                    configToSend.cache = diskConfig.cache;
                }
                // Only add iothread for scsi/virtio
                if (supportsIothread && diskConfig.iothread) {
                    configToSend.iothread = true;
                }
                // Only add ssd for scsi/virtio/sata
                if (supportsSsd && diskConfig.ssd) {
                    configToSend.ssd = true;
                }
                onAdd(configToSend);
            };

            return(
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                    <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in">
                        <h3 className="text-lg font-semibold text-white mb-4">{t('addDisk')}</h3>
                        <div className="space-y-4">
                            {isQemu && hardwareOptions && (
                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">Bus/Device</label>
                                        <select
                                            value={currentBus}
                                            onChange={(e) => handleBusChange(e.target.value)}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                        >
                                            {(hardwareOptions?.disk_bus_types || [{value: 'scsi', label: 'SCSI'}]).map(bus => (
                                                <option key={bus.value} value={bus.value}>{bus.label}</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">ID</label>
                                        <input
                                            type="text"
                                            value={diskConfig.disk_id}
                                            onChange={(e) => setDiskConfig({...diskConfig, disk_id: e.target.value})}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                        />
                                    </div>
                                </div>
                            )}
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">Storage</label>
                                    <select
                                        value={diskConfig.storage}
                                        onChange={(e) => setDiskConfig({...diskConfig, storage: e.target.value})}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                    >
                                        {storageList.map(s => {
                                            const freeBytes = s.avail || s.free || 0;
                                            const totalBytes = s.total || 0;
                                            const usedPercent = totalBytes > 0 ? Math.round((1 - freeBytes / totalBytes) * 100) : 0;
                                            const freeGB = (freeBytes / (1024 * 1024 * 1024)).toFixed(1);
                                            const totalGB = (totalBytes / (1024 * 1024 * 1024)).toFixed(1);
                                            return(
                                                <option key={s.storage} value={s.storage}>
                                                    {s.storage} ({freeGB} GB {t('free')} / {totalGB} GB - {usedPercent}% {t('used')})
                                                </option>
                                            );
                                        })}
                                    </select>
                                    {/* Show selected storage details */}
                                    {diskConfig.storage && storageList.length > 0 && (() => {
                                        const selected = storageList.find(s => s.storage === diskConfig.storage);
                                        if (!selected) return null;
                                        const freeBytes = selected.avail || selected.free || 0;
                                        const totalBytes = selected.total || 0;
                                        const usedPercent = totalBytes > 0 ? Math.round((1 - freeBytes / totalBytes) * 100) : 0;
                                        const freeGB = (freeBytes / (1024 * 1024 * 1024)).toFixed(1);
                                        return(
                                            <div className="mt-2 p-2 bg-proxmox-darker rounded-lg">
                                                <div className="flex justify-between text-xs mb-1">
                                                    <span className="text-gray-400">{t('freeSpace') || 'Free'}:</span>
                                                    <span className={`font-medium ${freeBytes < diskConfig.size * 1024 * 1024 * 1024 ? 'text-red-400' : 'text-green-400'}`}>
                                                        {freeGB} GB
                                                    </span>
                                                </div>
                                                <div className="h-1.5 bg-proxmox-dark rounded-full overflow-hidden">
                                                    <div 
                                                        className={`h-full rounded-full transition-all ${usedPercent > 90 ? 'bg-red-500' : usedPercent > 70 ? 'bg-yellow-500' : 'bg-green-500'}`}
                                                        style={{ width: `${usedPercent}%` }}
                                                    />
                                                </div>
                                                {freeBytes < diskConfig.size * 1024 * 1024 * 1024 && diskConfig.size > 0 && (
                                                    <p className="text-xs text-red-400 mt-1">⚠️ {t('notEnoughSpace') || 'Not enough space!'}</p>
                                                )}
                                            </div>
                                        );
                                    })()}
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">{t('size')} (GB)</label>
                                    <input
                                        type="number"
                                        value={diskConfig.size}
                                        onChange={(e) => setDiskConfig({...diskConfig, size: parseInt(e.target.value) || 0})}
                                        min="1"
                                        placeholder="32"
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                    />
                                </div>
                            </div>
                            {isQemu && hardwareOptions && (
                                <React.Fragment>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">Cache</label>
                                        <select
                                            value={diskConfig.cache}
                                            onChange={(e) => setDiskConfig({...diskConfig, cache: e.target.value})}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                        >
                                            {(hardwareOptions?.cache_modes || [{value: '', label: 'Default'}]).map(c => (
                                                <option key={c.value} value={c.value}>{c.label}</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div className="flex flex-wrap gap-4">
                                        {/* MK: IO Thread only for SCSI and VirtIO */}
                                        {supportsIothread && (
                                            <label className="flex items-center gap-2 text-sm text-gray-300">
                                                <input type="checkbox" checked={diskConfig.iothread} onChange={(e) => setDiskConfig({...diskConfig, iothread: e.target.checked})} className="rounded" />
                                                IO Thread
                                            </label>
                                        )}
                                        {/* MK: SSD Emulation for SCSI, VirtIO, SATA (not IDE) */}
                                        {supportsSsd && (
                                            <label className="flex items-center gap-2 text-sm text-gray-300">
                                                <input type="checkbox" checked={diskConfig.ssd} onChange={(e) => setDiskConfig({...diskConfig, ssd: e.target.checked})} className="rounded" />
                                                SSD Emulation
                                            </label>
                                        )}
                                        <label className="flex items-center gap-2 text-sm text-gray-300">
                                            <input type="checkbox" checked={diskConfig.discard} onChange={(e) => setDiskConfig({...diskConfig, discard: e.target.checked})} className="rounded" />
                                            Discard
                                        </label>
                                    </div>
                                </React.Fragment>
                            )}
                        </div>
                        <div className="flex justify-end gap-3 mt-6">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">{t('cancel')}</button>
                            <button onClick={handleAdd} className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600">{t('add')}</button>
                        </div>
                    </div>
                </div>
            );
        }

        function ResizeDiskModal({ disk, onResize, onClose }) {
            const { t } = useTranslation();
            const [size, setSize] = useState('+10G');
            return(
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                    <div className="w-full max-w-sm bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in">
                        <h3 className="text-lg font-semibold text-white mb-4">{t('resizeDisk') || 'Resize Disk'}</h3>
                        <p className="text-sm text-gray-400 mb-4">Aktuelle Groesse: {disk.size}</p>
                        <div>
                            <label className="block text-xs text-gray-400 mb-1">{t('resizeDiskHint') || 'Increase by (e.g. +10G) or new size'}</label>
                            <input
                                type="text"
                                value={size}
                                onChange={(e) => setSize(e.target.value)}
                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                            />
                        </div>
                        <div className="flex justify-end gap-3 mt-6">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">{t('cancel')}</button>
                            <button onClick={() => onResize(size)} className="px-4 py-2 bg-green-600 rounded-lg text-white hover:bg-green-700">Vergroessern</button>
                        </div>
                    </div>
                </div>
            );
        }

        // MK: Modal for reattaching unused disks with bus type selection
        // LW: Jan 2026 - Makes it easier to reattach disks with correct settings
        function ReattachDiskModal({ disk, getNextDiskId, onReattach, onClose }) {
            const { t } = useTranslation();
            const [busType, setBusType] = useState('scsi');
            const [diskId, setDiskId] = useState(getNextDiskId('scsi'));
            const [iothread, setIothread] = useState(true);
            const [ssd, setSsd] = useState(false);
            const [discard, setDiscard] = useState(true);
            const [loading, setLoading] = useState(false);
            
            // MK: Update disk ID when bus type changes
            const handleBusChange = (newBus) => {
                setBusType(newBus);
                setDiskId(getNextDiskId(newBus));
                // Reset unsupported options
                if (!['scsi', 'virtio'].includes(newBus)) {
                    setIothread(false);
                }
                if (!['scsi', 'virtio', 'sata'].includes(newBus)) {
                    setSsd(false);
                }
            };
            
            // LW: Check which options are supported
            const supportsIothread = ['scsi', 'virtio'].includes(busType);
            const supportsSsd = ['scsi', 'virtio', 'sata'].includes(busType);
            
            const busTypes = [
                { value: 'scsi', label: 'SCSI', desc: t('scsiDesc') || 'Best performance with VirtIO SCSI controller' },
                { value: 'virtio', label: 'VirtIO Block', desc: t('virtioDesc') || 'Legacy VirtIO, good performance' },
                { value: 'sata', label: 'SATA', desc: t('sataDesc') || 'Good compatibility, moderate performance' },
                { value: 'ide', label: 'IDE', desc: t('ideDesc') || 'Maximum compatibility, lowest performance' },
            ];
            
            const handleReattach = async () => {
                if (loading) return;
                setLoading(true);
                
                // MK: Build disk options string
                let options = [];
                if (supportsIothread && iothread) options.push('iothread=1');
                if (supportsSsd && ssd) options.push('ssd=1');
                if (discard) options.push('discard=on');
                
                const diskValue = options.length > 0 
                    ? `${disk.value},${options.join(',')}` 
                    : disk.value;
                
                try {
                    await onReattach(diskId, diskValue);
                } finally {
                    setLoading(false);
                }
            };
            
            return (
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                    <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in">
                        <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
                            <Icons.HardDrive className="text-green-400" />
                            {t('reattachDisk') || 'Reattach Disk'}
                        </h3>
                        <p className="text-sm text-gray-400 mb-4">
                            {t('volume') || 'Volume'}: <span className="font-mono text-white">{disk.value}</span>
                        </p>
                        
                        {/* Bus Type Selection */}
                        <div className="mb-4">
                            <label className="block text-xs text-gray-400 mb-2">{t('selectBusType') || 'Select Bus Type'}</label>
                            <div className="grid grid-cols-2 gap-2">
                                {busTypes.map(bus => (
                                    <button
                                        key={bus.value}
                                        onClick={() => handleBusChange(bus.value)}
                                        disabled={loading}
                                        className={`p-3 rounded-lg text-left transition-all ${
                                            busType === bus.value
                                                ? 'bg-green-600/20 border border-green-500'
                                                : 'bg-proxmox-dark border border-proxmox-border hover:border-gray-500'
                                        }`}
                                    >
                                        <div className="font-medium text-white text-sm">{bus.label}</div>
                                        <div className="text-xs text-gray-500 mt-0.5">{bus.desc}</div>
                                    </button>
                                ))}
                            </div>
                        </div>
                        
                        {/* Disk ID */}
                        <div className="mb-4">
                            <label className="block text-xs text-gray-400 mb-1">{t('diskId') || 'Disk ID'}</label>
                            <input
                                type="text"
                                value={diskId}
                                onChange={(e) => setDiskId(e.target.value)}
                                disabled={loading}
                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm font-mono"
                            />
                            <p className="text-xs text-gray-500 mt-1">{t('nextAvailableId') || 'Next available ID for selected bus type'}</p>
                        </div>
                        
                        {/* Options */}
                        <div className="mb-4 p-3 bg-proxmox-dark rounded-lg border border-proxmox-border">
                            <label className="block text-xs text-gray-400 mb-2">{t('diskOptions') || 'Disk Options'}</label>
                            <div className="flex flex-wrap gap-4">
                                {supportsIothread && (
                                    <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                                        <input 
                                            type="checkbox" 
                                            checked={iothread} 
                                            onChange={(e) => setIothread(e.target.checked)} 
                                            disabled={loading}
                                            className="rounded" 
                                        />
                                        IO Thread
                                    </label>
                                )}
                                {supportsSsd && (
                                    <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                                        <input 
                                            type="checkbox" 
                                            checked={ssd} 
                                            onChange={(e) => setSsd(e.target.checked)} 
                                            disabled={loading}
                                            className="rounded" 
                                        />
                                        SSD Emulation
                                    </label>
                                )}
                                <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                                    <input 
                                        type="checkbox" 
                                        checked={discard} 
                                        onChange={(e) => setDiscard(e.target.checked)} 
                                        disabled={loading}
                                        className="rounded" 
                                    />
                                    Discard (TRIM)
                                </label>
                            </div>
                            {!supportsIothread && !supportsSsd && (
                                <p className="text-xs text-yellow-500 mt-2">
                                    {t('ideLimitedOptions') || 'IDE has limited options available'}
                                </p>
                            )}
                        </div>
                        
                        {/* Preview */}
                        <div className="mb-4 p-3 bg-proxmox-dark/50 rounded-lg border border-dashed border-proxmox-border">
                            <label className="block text-xs text-gray-400 mb-1">{t('preview') || 'Preview'}</label>
                            <div className="flex items-center gap-2">
                                <span className="text-green-400 font-mono font-medium">{diskId}</span>
                                <Icons.ArrowRight className="w-4 h-4 text-gray-500" />
                                <span className="text-gray-300 font-mono text-sm truncate">{disk.value}</span>
                            </div>
                        </div>
                        
                        <div className="flex justify-end gap-3">
                            <button 
                                onClick={onClose} 
                                disabled={loading}
                                className="px-4 py-2 text-gray-300 hover:text-white disabled:opacity-50"
                            >
                                {t('cancel')}
                            </button>
                            <button 
                                onClick={handleReattach}
                                disabled={loading || !diskId}
                                className="px-4 py-2 bg-green-600 rounded-lg text-white hover:bg-green-700 disabled:opacity-50 flex items-center gap-2"
                            >
                                {loading && <Icons.RotateCw className="w-4 h-4 animate-spin" />}
                                {loading ? (t('attaching') || 'Attaching...') : (t('reattach') || 'Reattach')}
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        // NS: Simple modal for moving disks between storages
        // Works with both local and shared storage
        function MoveDiskModal({ disk, storageList, onMove, onClose }) {
            const { t } = useTranslation();
            const [storage, setStorage] = useState(storageList.filter(s => s.storage !== disk.storage)[0]?.storage || '');
            const [deleteSource, setDeleteSource] = useState(true);
            return(
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                    <div className="w-full max-w-sm bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in">
                        <h3 className="text-lg font-semibold text-white mb-4">{t('moveDisk') || 'Move Disk'}</h3>
                        <p className="text-sm text-gray-400 mb-4">{disk.id} - {t('from') || 'from'} <span className="text-white font-mono">{disk.storage}</span></p>
                        <div>
                            <label className="block text-xs text-gray-400 mb-1">{t('targetStorage')}</label>
                            <select
                                value={storage}
                                onChange={(e) => setStorage(e.target.value)}
                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                            >
                                {storageList.filter(s => s.storage !== disk.storage).map(s => (
                                    <option key={s.storage} value={s.storage}>{s.storage}</option>
                                ))}
                            </select>
                        </div>
                        <div className="mt-4 flex items-center gap-3 p-3 bg-proxmox-dark rounded-lg border border-proxmox-border">
                            <Toggle checked={deleteSource} onChange={setDeleteSource} label={t('deleteSourceDisk') || 'Delete source after move'} />
                        </div>
                        {!deleteSource && (
                            <p className="mt-2 text-xs text-yellow-400/80">
                                {t('deleteSourceDiskWarning') || 'The original disk will remain on the source storage. You can remove it manually later.'}
                            </p>
                        )}
                        <div className="flex justify-end gap-3 mt-6">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">{t('cancel')}</button>
                            <button onClick={() => onMove(storage, deleteSource)} className="px-4 py-2 bg-blue-600 rounded-lg text-white hover:bg-blue-700">{t('move') || 'Move'}</button>
                        </div>
                    </div>
                </div>
            );
        }

        // MK: Edit Disk Bus Type Modal - allows changing disk from SCSI to IDE/SATA/VirtIO etc.
        // LW: Added Jan 2026 - users kept asking for this in Discord
        function EditDiskBusModal({ disk, hardwareOptions, vmStatus, onSave, onClose }) {
            const { t } = useTranslation();
            const currentBus = disk.id.replace(/[0-9]/g, '');
            const [newBus, setNewBus] = useState(currentBus);
            const [loading, setLoading] = useState(false);
            
            // MK: Check if VM is running - bus type change requires VM to be stopped
            const isVmRunning = vmStatus === 'running';
            
            // MK: Check which options will be stripped - use Boolean to avoid JSX rendering 0
            const hasIothread = Boolean(disk.iothread && disk.iothread > 0);
            const hasSsd = Boolean(disk.ssd && disk.ssd > 0);
            const willStripIothread = hasIothread && !['scsi', 'virtio'].includes(newBus);
            const willStripSsd = hasSsd && !['scsi', 'virtio', 'sata'].includes(newBus);
            
            const handleSave = async () => {
                if (loading || isVmRunning) return; // Prevent double-click and running VM
                setLoading(true);
                try {
                    await onSave(newBus);
                } finally {
                    setLoading(false);
                }
            };
            
            const busTypes = [
                { value: 'scsi', label: 'SCSI', desc: t('scsiDesc') || 'Best performance with VirtIO SCSI controller' },
                { value: 'virtio', label: 'VirtIO Block', desc: t('virtioDesc') || 'Legacy VirtIO, good performance' },
                { value: 'sata', label: 'SATA', desc: t('sataDesc') || 'Good compatibility, moderate performance' },
                { value: 'ide', label: 'IDE', desc: t('ideDesc') || 'Maximum compatibility, lowest performance' },
            ];
            
            return (
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                    <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in">
                        <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
                            <Icons.Edit className="text-yellow-400" />
                            {t('changeDiskBusType') || 'Change Disk Bus Type'}
                        </h3>
                        <p className="text-sm text-gray-400 mb-4">
                            {t('currentDisk') || 'Current'}: <span className="font-mono text-white">{disk.id}</span> ({disk.size})
                            {disk.iothread && <span className="ml-2 text-xs bg-green-500/20 text-green-400 px-1.5 py-0.5 rounded">IOthread</span>}
                            {disk.ssd && <span className="ml-1 text-xs bg-blue-500/20 text-blue-400 px-1.5 py-0.5 rounded">SSD</span>}
                        </p>
                        
                        {/* MK: Error if VM is running */}
                        {isVmRunning ? (
                            <div className="p-4 bg-red-500/20 border border-red-500/50 rounded-lg mb-4">
                                <div className="flex items-start gap-3">
                                    <Icons.AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0" />
                                    <div>
                                        <div className="font-medium text-red-400 mb-1">{t('vmIsRunning') || 'VM is running'}</div>
                                        <p className="text-sm text-red-300">{t('vmMustBeStoppedForBusChange') || 'The VM must be stopped before changing the disk bus type. Please shut down the VM first.'}</p>
                                    </div>
                                </div>
                            </div>
                        ) : (
                            <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-sm text-yellow-300 mb-4">
                                <div className="flex items-start gap-2">
                                    <Icons.AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                                    <div>{t('diskBusWarning') || 'Changing the bus type requires the VM to be stopped. The guest OS may need driver updates.'}</div>
                                </div>
                            </div>
                        )}
                        
                        {/* MK: Show warning about stripped options */}
                        {(willStripIothread || willStripSsd) && !isVmRunning && (
                            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-300 mb-4">
                                <div className="flex items-start gap-2">
                                    <Icons.Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
                                    <div>
                                        {t('optionsWillBeRemoved') || 'The following options are not supported and will be removed'}:
                                        {willStripIothread && <span className="ml-2 font-mono bg-red-500/20 px-1.5 py-0.5 rounded">IO Thread</span>}
                                        {willStripSsd && <span className="ml-2 font-mono bg-red-500/20 px-1.5 py-0.5 rounded">SSD</span>}
                                    </div>
                                </div>
                            </div>
                        )}
                        
                        <div className="space-y-2">
                            <label className="block text-xs text-gray-400 mb-2">{t('selectNewBusType') || 'Select new bus type'}</label>
                            {busTypes.map(bus => (
                                <label 
                                    key={bus.value}
                                    className={`flex items-center p-3 rounded-lg cursor-pointer transition-all ${
                                        newBus === bus.value 
                                            ? 'bg-proxmox-orange/20 border border-proxmox-orange' 
                                            : 'bg-proxmox-dark border border-proxmox-border hover:border-gray-500'
                                    } ${loading || isVmRunning ? 'opacity-50 pointer-events-none' : ''}`}
                                >
                                    <input
                                        type="radio"
                                        name="busType"
                                        value={bus.value}
                                        checked={newBus === bus.value}
                                        onChange={(e) => setNewBus(e.target.value)}
                                        disabled={loading || isVmRunning}
                                        className="mr-3"
                                    />
                                    <div className="flex-1">
                                        <div className="flex items-center gap-2">
                                            <span className="font-medium text-white">{bus.label}</span>
                                            {currentBus === bus.value && (
                                                <span className="text-xs bg-gray-600 px-2 py-0.5 rounded">{t('current') || 'Current'}</span>
                                            )}
                                        </div>
                                        <p className="text-xs text-gray-500 mt-0.5">{bus.desc}</p>
                                    </div>
                                </label>
                            ))}
                        </div>
                        
                        <div className="flex justify-end gap-3 mt-6">
                            <button onClick={onClose} disabled={loading} className="px-4 py-2 text-gray-300 hover:text-white disabled:opacity-50">{t('cancel')}</button>
                            <button 
                                onClick={handleSave} 
                                disabled={newBus === currentBus || loading || isVmRunning}
                                className="px-4 py-2 bg-yellow-600 rounded-lg text-white hover:bg-yellow-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                            >
                                {loading && <Icons.RotateCw className="w-4 h-4 animate-spin" />}
                                {isVmRunning ? (t('vmMustBeStopped') || 'VM must be stopped') : loading ? (t('saving') || 'Saving...') : (t('changeBusType') || 'Change Bus Type')}
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        function MountISOModal({ isoList, existingDrives, onMount, onClose }) {
            const { t } = useTranslation();
            const [iso, setIso] = useState('');
            const [driveType, setDriveType] = useState('ide');
            const [driveNum, setDriveNum] = useState('2');
            
            // calc which drives are already in use
            const usedDrives = existingDrives || [];
            
            // Available drive options
            const driveOptions = [
                { type: 'ide', nums: ['0', '1', '2', '3'], label: 'IDE' },
                { type: 'scsi', nums: ['0', '1', '2', '3', '4', '5'], label: 'SCSI' },
                { type: 'sata', nums: ['0', '1', '2', '3', '4', '5'], label: 'SATA' },
            ];
            
            const currentDrive = `${driveType}${driveNum}`;
            const currentDriveInfo = usedDrives.find(d => d.key === currentDrive);
            const isDriveUsedByDisk = currentDriveInfo && !currentDriveInfo.isCdrom;
            const isDriveCdrom = currentDriveInfo?.isCdrom;
            
            // Find first free or cdrom slot when changing drive type
            const findBestSlot = (type) => {
                const nums = driveOptions.find(o => o.type === type)?.nums || [];
                // First try to find existing CD-ROM
                for (const num of nums) {
                    const drive = `${type}${num}`;
                    const info = usedDrives.find(d => d.key === drive);
                    if (info?.isCdrom) return num;
                }
                // Then find free slot
                for (const num of nums) {
                    const drive = `${type}${num}`;
                    const info = usedDrives.find(d => d.key === drive);
                    if (!info) return num;
                }
                // Default to first
                return nums[0];
            };
            
            return(
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                    <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in">
                        <h3 className="text-lg font-semibold text-white mb-4">{t('mountIso')}</h3>
                        
                        <div className="space-y-4">
                            {/* ISO Selection */}
                            <div>
                                <label className="block text-xs text-gray-400 mb-1">{t('isoImage')}</label>
                                <select
                                    value={iso}
                                    onChange={(e) => setIso(e.target.value)}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                >
                                    <option value="">-- {t('noIsoEject')} --</option>
                                    {isoList.map(i => (
                                        <option key={i.volid} value={i.volid}>{i.volid.split('/').pop()}</option>
                                    ))}
                                </select>
                            </div>
                            
                            {/* Drive Type Selection */}
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">{t('busType')}</label>
                                    <select
                                        value={driveType}
                                        onChange={(e) => {
                                            const newType = e.target.value;
                                            setDriveType(newType);
                                            setDriveNum(findBestSlot(newType));
                                        }}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                    >
                                        {driveOptions.map(opt => (
                                            <option key={opt.type} value={opt.type}>{opt.label}</option>
                                        ))}
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">{t('device')}</label>
                                    <select
                                        value={driveNum}
                                        onChange={(e) => setDriveNum(e.target.value)}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                    >
                                        {driveOptions.find(o => o.type === driveType)?.nums.map(num => {
                                            const drive = `${driveType}${num}`;
                                            const info = usedDrives.find(d => d.key === drive);
                                            const isUsedByDisk = info && !info.isCdrom;
                                            const isCdrom = info?.isCdrom;
                                            
                                            let label = drive;
                                            if (isCdrom) label += ` (${t('cdrom')})`;
                                            else if (isUsedByDisk) label += ` (${t('hardDisk')})`;
                                            
                                            return(
                                                <option 
                                                    key={num} 
                                                    value={num}
                                                    disabled={isUsedByDisk}
                                                    style={isUsedByDisk ? {color: '#666'} : {}}
                                                >
                                                    {label}
                                                </option>
                                            );
                                        })}
                                    </select>
                                </div>
                            </div>
                            
                            {/* Drive info */}
                            <div className="text-xs">
                                <span className="text-gray-500">{t('target')}: </span>
                                <span className="text-proxmox-orange font-mono">{currentDrive}</span>
                                {isDriveCdrom && (
                                    <span className="text-green-500 ml-2">✓ {t('existingCdrom')}</span>
                                )}
                                {isDriveUsedByDisk && (
                                    <span className="text-red-500 ml-2">✗ {t('hardDiskNotAvailable')}</span>
                                )}
                                {!currentDriveInfo && (
                                    <span className="text-blue-400 ml-2">â—‹ {t('freeSlot')}</span>
                                )}
                            </div>
                        </div>
                        
                        <div className="flex justify-end gap-3 mt-6">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">{t('cancel')}</button>
                            <button 
                                onClick={() => onMount(iso || null, currentDrive)} 
                                disabled={isDriveUsedByDisk}
                                className={`px-4 py-2 rounded-lg text-white ${
                                    isDriveUsedByDisk 
                                        ? 'bg-gray-600 cursor-not-allowed' 
                                        : 'bg-proxmox-orange hover:bg-orange-600'
                                }`}
                            >
                                {iso ? t('mount') : t('eject')}
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        function AddNetworkModal({ isQemu, bridgeList, hardwareOptions, getNextNetId, generateMAC, onAdd, onClose }) {
            const { t } = useTranslation();
            const [netConfig, setNetConfig] = useState({
                net_id: 'net1',
                bridge: bridgeList[0]?.iface || 'vmbr0',
                model: 'virtio',
                macaddr: '',
                firewall: true,
                tag: '',
                rate: '',
                mtu: '',
                queues: '',
                name: 'eth0',
                ip: 'dhcp',
                gw: '',
                ip6: '',
                gw6: '',
                hwaddr: '',
            });

            useEffect(() => {
                if (getNextNetId) {
                    setNetConfig(prev => ({...prev, net_id: getNextNetId()}));
                }
            }, []);

            return(
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                    <div className="w-full max-w-lg bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in max-h-[80vh] overflow-y-auto">
                        <h3 className="text-lg font-semibold text-white mb-4">{t('addNetwork')}</h3>
                        <div className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">Interface ID</label>
                                    <input type="text" value={netConfig.net_id} onChange={(e) => setNetConfig({...netConfig, net_id: e.target.value})}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">Bridge / VNet</label>
                                    <select value={netConfig.bridge} onChange={(e) => setNetConfig({...netConfig, bridge: e.target.value})}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm">
                                        {/* Local bridges */}
                                        {bridgeList.filter(b => b.source !== 'sdn').length > 0 && (
                                            <optgroup label="Local Bridges">
                                                {bridgeList.filter(b => b.source !== 'sdn').map(b => (
                                                    <option key={b.iface} value={b.iface}>{b.iface}{b.comments ? ` - ${b.comments}` : ''}</option>
                                                ))}
                                            </optgroup>
                                        )}
                                        {/* SDN VNets */}
                                        {bridgeList.filter(b => b.source === 'sdn').length > 0 && (
                                            <optgroup label="SDN VNets">
                                                {bridgeList.filter(b => b.source === 'sdn').map(b => (
                                                    <option key={b.iface} value={b.iface}>{b.iface} - {b.zone || 'SDN'}{b.alias ? ` (${b.alias})` : ''}</option>
                                                ))}
                                            </optgroup>
                                        )}
                                        {/* Fallback if no bridges loaded */}
                                        {bridgeList.length === 0 && <option value="vmbr0">vmbr0</option>}
                                    </select>
                                </div>
                            </div>
                            {isQemu && hardwareOptions && (
                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">Model</label>
                                        <select value={netConfig.model} onChange={(e) => setNetConfig({...netConfig, model: e.target.value})}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm">
                                            {(hardwareOptions?.network_models || [{value: 'virtio', label: 'VirtIO'}]).map(m => (<option key={m.value} value={m.value}>{m.label}</option>))}
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">MAC Adresse</label>
                                        <div className="flex gap-2">
                                            <input type="text" value={netConfig.macaddr} onChange={(e) => setNetConfig({...netConfig, macaddr: e.target.value})}
                                                placeholder="auto" className="flex-1 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                            <button onClick={() => setNetConfig({...netConfig, macaddr: generateMAC()})}
                                                className="px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-400 hover:text-white text-sm">
                                                <Icons.RefreshCw />
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            )}
                            {!isQemu && (
                                <>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-xs text-gray-400 mb-1">Interface Name</label>
                                            <input type="text" value={netConfig.name} onChange={(e) => setNetConfig({...netConfig, name: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                        </div>
                                        <div>
                                            <label className="block text-xs text-gray-400 mb-1">MAC Adresse</label>
                                            <div className="flex gap-2">
                                                <input type="text" value={netConfig.hwaddr} onChange={(e) => setNetConfig({...netConfig, hwaddr: e.target.value})}
                                                    placeholder="auto" className="flex-1 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                                <button onClick={() => setNetConfig({...netConfig, hwaddr: generateMAC()})}
                                                    className="px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-400 hover:text-white">
                                                    <Icons.RefreshCw />
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-xs text-gray-400 mb-1">IPv4</label>
                                            <input type="text" value={netConfig.ip} onChange={(e) => setNetConfig({...netConfig, ip: e.target.value})}
                                                placeholder="dhcp or 10.0.0.10/24" className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                        </div>
                                        <div>
                                            <label className="block text-xs text-gray-400 mb-1">Gateway</label>
                                            <input type="text" value={netConfig.gw} onChange={(e) => setNetConfig({...netConfig, gw: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                        </div>
                                    </div>
                                </>
                            )}
                            <div className="grid grid-cols-3 gap-4">
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">VLAN Tag</label>
                                    <input type="text" value={netConfig.tag} onChange={(e) => setNetConfig({...netConfig, tag: e.target.value})}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">Rate (MB/s)</label>
                                    <input type="text" value={netConfig.rate} onChange={(e) => setNetConfig({...netConfig, rate: e.target.value})}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">MTU</label>
                                    <input type="text" value={netConfig.mtu} onChange={(e) => setNetConfig({...netConfig, mtu: e.target.value})}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                </div>
                            </div>
                            <label className="flex items-center gap-2 text-sm text-gray-300">
                                <input type="checkbox" checked={netConfig.firewall} onChange={(e) => setNetConfig({...netConfig, firewall: e.target.checked})} className="rounded" />
                                {t('enableFirewall')}
                            </label>
                        </div>
                        <div className="flex justify-end gap-3 mt-6">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">{t('cancel')}</button>
                            <button onClick={() => onAdd(netConfig)} className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600">{t('add')}</button>
                        </div>
                    </div>
                </div>
            );
        }

        function EditNetworkModal({ isQemu, network, bridgeList, hardwareOptions, generateMAC, onUpdate, onClose }) {
            const { t } = useTranslation();
            const [editConfig, setEditConfig] = useState({
                bridge: network.bridge || 'vmbr0',
                model: network.model || 'virtio',
                macaddr: network.macaddr || '',
                firewall: network.firewall || false,
                tag: network.tag || '',
                rate: network.rate || '',
                mtu: network.mtu || '',
                queues: network.queues || '',  // LW: Multiqueue support
                link_down: network.link_down || false,  // NS: Disconnect checkbox
                name: network.name || 'eth0',
                ip: network.ip || 'dhcp',
                gw: network.gw || '',
                hwaddr: network.hwaddr || '',
            });

            return(
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60">
                    <div className="w-full max-w-lg bg-proxmox-card border border-proxmox-border rounded-xl p-6 animate-scale-in max-h-[80vh] overflow-y-auto">
                        <h3 className="text-lg font-semibold text-white mb-4">{t('editNetwork')}: {network.id}</h3>
                        <div className="space-y-4">
                            {/* Disconnect Checkbox - prominent at top for QEMU */}
                            {isQemu && (
                                <div className={`p-3 rounded-lg border ${editConfig.link_down ? 'bg-red-500/10 border-red-500/30' : 'bg-proxmox-dark border-proxmox-border'}`}>
                                    <label className="flex items-center gap-3 cursor-pointer">
                                        <input 
                                            type="checkbox" 
                                            checked={editConfig.link_down} 
                                            onChange={(e) => setEditConfig({...editConfig, link_down: e.target.checked})} 
                                            className="w-4 h-4 rounded" 
                                        />
                                        <div>
                                            <span className={`text-sm font-medium ${editConfig.link_down ? 'text-red-400' : 'text-gray-300'}`}>
                                                {t('disconnectNetwork')}
                                            </span>
                                            <p className="text-xs text-gray-500">{t('disconnectNetworkHint')}</p>
                                        </div>
                                    </label>
                                </div>
                            )}
                            
                            <div>
                                <label className="block text-xs text-gray-400 mb-1">Bridge / VNet</label>
                                <select value={editConfig.bridge} onChange={(e) => setEditConfig({...editConfig, bridge: e.target.value})}
                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm">
                                    {/* Include current bridge if not in list (important for SDN VNets) */}
                                    {editConfig.bridge && !bridgeList.find(b => b.iface === editConfig.bridge) && (
                                        <option value={editConfig.bridge}>{editConfig.bridge} (current)</option>
                                    )}
                                    {/* Local bridges */}
                                    {bridgeList.filter(b => b.source !== 'sdn').length > 0 && (
                                        <optgroup label="Local Bridges">
                                            {bridgeList.filter(b => b.source !== 'sdn').map(b => (
                                                <option key={b.iface} value={b.iface}>{b.iface}{b.comments ? ` - ${b.comments}` : ''}</option>
                                            ))}
                                        </optgroup>
                                    )}
                                    {/* SDN VNets */}
                                    {bridgeList.filter(b => b.source === 'sdn').length > 0 && (
                                        <optgroup label="SDN VNets">
                                            {bridgeList.filter(b => b.source === 'sdn').map(b => (
                                                <option key={b.iface} value={b.iface}>{b.iface} - {b.zone || 'SDN'}{b.alias ? ` (${b.alias})` : ''}</option>
                                            ))}
                                        </optgroup>
                                    )}
                                    {/* Fallback if no bridges loaded */}
                                    {bridgeList.length === 0 && <option value="vmbr0">vmbr0</option>}
                                </select>
                            </div>
                            {isQemu && hardwareOptions && (
                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">Model</label>
                                        <select value={editConfig.model} onChange={(e) => setEditConfig({...editConfig, model: e.target.value})}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm">
                                            {(hardwareOptions?.network_models || [{value: 'virtio', label: 'VirtIO'}]).map(m => (<option key={m.value} value={m.value}>{m.label}</option>))}
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">MAC Adresse</label>
                                        <div className="flex gap-2">
                                            <input type="text" value={editConfig.macaddr} onChange={(e) => setEditConfig({...editConfig, macaddr: e.target.value})}
                                                className="flex-1 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                            <button onClick={() => setEditConfig({...editConfig, macaddr: generateMAC()})}
                                                className="px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-400 hover:text-white">
                                                <Icons.RefreshCw />
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            )}
                            {!isQemu && (
                                <React.Fragment>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-xs text-gray-400 mb-1">Interface Name</label>
                                            <input type="text" value={editConfig.name} onChange={(e) => setEditConfig({...editConfig, name: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                        </div>
                                        <div>
                                            <label className="block text-xs text-gray-400 mb-1">MAC</label>
                                            <div className="flex gap-2">
                                                <input type="text" value={editConfig.hwaddr} onChange={(e) => setEditConfig({...editConfig, hwaddr: e.target.value})}
                                                    className="flex-1 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm font-mono" />
                                                <button onClick={() => setEditConfig({...editConfig, hwaddr: generateMAC()})}
                                                    className="px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-400 hover:text-white">
                                                    <Icons.RefreshCw />
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-xs text-gray-400 mb-1">IPv4</label>
                                            <input type="text" value={editConfig.ip} onChange={(e) => setEditConfig({...editConfig, ip: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                        </div>
                                        <div>
                                            <label className="block text-xs text-gray-400 mb-1">Gateway</label>
                                            <input type="text" value={editConfig.gw} onChange={(e) => setEditConfig({...editConfig, gw: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                        </div>
                                    </div>
                                </React.Fragment>
                            )}
                            
                            {/* Network Settings Grid */}
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">VLAN Tag</label>
                                    <input type="text" value={editConfig.tag} onChange={(e) => setEditConfig({...editConfig, tag: e.target.value})}
                                        placeholder="z.B. 100"
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">MTU</label>
                                    <input type="number" value={editConfig.mtu} onChange={(e) => setEditConfig({...editConfig, mtu: e.target.value})}
                                        placeholder="1500"
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                </div>
                            </div>
                            
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">Rate Limit (MB/s)</label>
                                    <input type="number" value={editConfig.rate} onChange={(e) => setEditConfig({...editConfig, rate: e.target.value})}
                                        placeholder={t('unlimited')}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                </div>
                                {/* Multiqueue - only for QEMU with virtio */}
                                {isQemu && (
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">Multiqueue</label>
                                        <input type="number" value={editConfig.queues} onChange={(e) => setEditConfig({...editConfig, queues: e.target.value})}
                                            placeholder="1"
                                            min="1" max="64"
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                        <p className="text-xs text-gray-500 mt-1">1-64 Queues (nur VirtIO)</p>
                                    </div>
                                )}
                            </div>
                            
                            <label className="flex items-center gap-2 text-sm text-gray-300">
                                <input type="checkbox" checked={editConfig.firewall} onChange={(e) => setEditConfig({...editConfig, firewall: e.target.checked})} className="rounded" />
                                {t('enableFirewall')}
                            </label>
                        </div>
                        <div className="flex justify-end gap-3 mt-6">
                            <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">{t('cancel')}</button>
                            <button onClick={() => onUpdate(editConfig)} className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600">{t('save')}</button>
                        </div>
                    </div>
                </div>
            );
        }

