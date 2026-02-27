        // ═══════════════════════════════════════════════
        // PegaProx - Storage
        // DatastoreTab with storage cluster balancing
        // ═══════════════════════════════════════════════
        // Datastore Tab Component - with Storage Clusters for balancing
        function DatastoreTab({ clusterId, addToast }) {
            const { t } = useTranslation();
            const { getAuthHeaders, isAdmin } = useAuth();
            const [loading, setLoading] = useState(true);
            const [datastores, setDatastores] = useState({ shared: [], local: {}, nodes: [] });
            const [selectedStorage, setSelectedStorage] = useState(null);
            const [storageContent, setStorageContent] = useState([]);
            const [contentLoading, setContentLoading] = useState(false);
            const [expandedNodes, setExpandedNodes] = useState({});
            const [activeTab, setActiveTab] = useState('browse'); // browse, balancing
            const [uploadModalOpen, setUploadModalOpen] = useState(false);
            const [uploadFile, setUploadFile] = useState(null);
            const [uploading, setUploading] = useState(false);
            const [uploadProgress, setUploadProgress] = useState(0);
            const [uploadSpeed, setUploadSpeed] = useState(0);
            const [deleteConfirm, setDeleteConfirm] = useState(null);
            const [isRefreshing, setIsRefreshing] = useState(false);  // not used
            const lastFetchTime = useRef(0);  // for rate limiting, not implemented
            
            // NS: URL Download state - Jan 2026
            const [downloadUrlModalOpen, setDownloadUrlModalOpen] = useState(false);
            const [downloadUrl, setDownloadUrl] = useState('');
            const [downloadFilename, setDownloadFilename] = useState('');
            const [urlDownloading, setUrlDownloading] = useState(false);
            const [urlDownloadProgress, setUrlDownloadProgress] = useState(null);
            
            // NS: Template download state - Jan 2026
            const [showTemplateModal, setShowTemplateModal] = useState(false);
            const [availableTemplates, setAvailableTemplates] = useState([]);
            const [templatesLoading, setTemplatesLoading] = useState(false);
            const [templateFilter, setTemplateFilter] = useState('');
            const [downloadingTemplate, setDownloadingTemplate] = useState(null);
            
            // MK: Storage Rescan modal state - Feb 2026
            const [showRescanModal, setShowRescanModal] = useState(false);
            const [rescanLoading, setRescanLoading] = useState(false);
            
            // Refs to prevent unnecessary re-renders and track state
            const datastoresRef = useRef(null);
            const fetchingRef = useRef(false);
            const initialLoadDone = useRef(false);
            const _mountedRef = useRef(true);  // cleanup
            
            // Storage Clusters state
            const [storageClusters, setStorageClusters] = useState([]);
            const [selectedCluster, setSelectedCluster] = useState(null);
            const [clusterStatus, setClusterStatus] = useState(null);
            const [showCreateCluster, setShowCreateCluster] = useState(false);
            const [newClusterName, setNewClusterName] = useState('');
            const [newClusterStorages, setNewClusterStorages] = useState([]);
            const [newClusterThreshold, setNewClusterThreshold] = useState(20);
            const [balancingLoading, setBalancingLoading] = useState(false);
            
            // NS: ESXi Integration state - Dec 2025
            const [esxiHosts, setEsxiHosts] = useState([]);
            const [showAddEsxi, setShowAddEsxi] = useState(false);
            const [esxiForm, setEsxiForm] = useState({ host: '', username: 'root', password: '' });
            const [esxiLoading, setEsxiLoading] = useState(false);
            const [selectedEsxi, setSelectedEsxi] = useState(null);
            const [esxiVms, setEsxiVms] = useState([]);
            const [esxiVmsLoading, setEsxiVmsLoading] = useState(false);
            
            // Debounce timer for threshold updates
            const thresholdTimer = useRef(null);
            
            /* LW: wrapped fetch with auth headers + error handling
               returns null on failure so you can do: if(!res) return; */
            const authFetch = async (url, opts = {}) => {
                try {
                    const res = await fetch(url, { ...opts, credentials: 'include', headers: { ...opts.headers, ...getAuthHeaders() } });
                    return res;
                } catch (e) {
                    console.error('fetch failed:', e);
                    return null;
                }
            };
            
            // old helper, keeping for now
            const _authFetchOld = async (url, options) => {
                return fetch(url, { ...options, headers: { ...options?.headers, ...getAuthHeaders() } })
                  .catch(err => { console.error(err); return null })
            };
            
            // NS: Load available templates from Proxmox repository
            const loadAvailableTemplates = async () => {
                setTemplatesLoading(true);
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/templates/available`);
                    if (res?.ok) {
                        const data = await res.json();
                        setAvailableTemplates(data || []);
                    } else {
                        console.error('Failed to load templates');
                    }
                } catch (e) {
                    console.error('Error loading templates:', e);
                }
                setTemplatesLoading(false);
            };
            
            // NS: Download template to storage
            const downloadTemplate = async (template, storage) => {
                setDownloadingTemplate(template.template);
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/templates/download`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            storage: storage,
                            template: template.template
                        })
                    });
                    if (res?.ok) {
                        const data = await res.json();
                        addToast(`${t('downloadStarted') || 'Download started'}: ${template.package || template.template}`, 'success');
                        // Refresh storage content after a short delay
                        setTimeout(() => {
                            if (selectedStorage?.name === storage) {
                                loadStorageContent(storage, selectedStorage.node);
                            }
                        }, 2000);
                    } else {
                        const err = await res.json();
                        addToast(`${t('downloadFailed') || 'Download failed'}: ${err.error || 'Unknown error'}`, 'error');
                    }
                } catch (e) {
                    console.error('Error downloading template:', e);
                    addToast(`${t('error') || 'Error'}: ${e.message}`, 'error');
                }
                setDownloadingTemplate(null);
            };
            
            // Stable sort function - always sorts alphabetically
            const stableSortData = (data) => {
                if (!data) return data;
                
                // sort shared alphabeticaly
                const sortedShared = [...(data.shared || [])].sort((a, b) => 
                    (a.storage || '').localeCompare(b.storage || '')
                );
                
                // sort nodes  
                const sortedNodes = [...(data.nodes || [])].sort((a, b) => a.localeCompare(b));
                
                // sort local per node
                const sortedLocal = {};
                for (const node of sortedNodes) {
                    if (data.local && data.local[node]) {
                        sortedLocal[node] = [...data.local[node]].sort((a, b) => 
                            (a.storage || '').localeCompare(b.storage || '')
                        );
                    }
                }
                
                return {
                    shared: sortedShared,
                    local: sortedLocal,
                    nodes: sortedNodes
                };
            };
            
            useEffect(() => {
                // LW: Reset ALL cluster-specific state when cluster changes
                // This prevents showing stale data from previous cluster
                setSelectedStorage(null);
                setStorageContent([]);
                setStorageClusters([]);  // NS: also reset storage clusters
                setSelectedCluster(null);
                setClusterStatus(null);
                setEsxiHosts([]);  // NS: reset ESXi hosts too
                setSelectedEsxi(null);
                setEsxiVms([]);
                
                // Reset refs
                initialLoadDone.current = false;  // Allow loading spinner again
                datastoresRef.current = null;  // Clear cached data
                fetchingRef.current = false;  // Reset fetch lock
                
                fetchDatastores();
                fetchStorageClusters();
            }, [clusterId]);
            
            const fetchDatastores = async () => {
                // prevent concurrent fetches
                if (fetchingRef.current) return;
                fetchingRef.current = true;
                
                // Only show loading spinner on initial load
                if (!initialLoadDone.current) {
                    setLoading(true);
                }
                
                try {
                    const resp = await authFetch(`${API_URL}/clusters/${clusterId}/datastores`);
                    if (resp && resp.ok) {
                        const rawData = await resp.json();
                        // console.log('datastores raw:', rawData);
                        
                        // Apply stable sorting
                        const data = stableSortData(rawData);
                        
                        // Create a comparable string (only compare essential data, not usage which changes)
                        // ns: this is kinda hacky but prevents flickering
                        const getEssentialData = (d) => ({
                            shared: d.shared?.map(s => s.storage).sort(),
                            nodes: d.nodes?.sort(),
                            localKeys: Object.keys(d.local || {}).sort()
                        });
                        
                        const currentEssential = JSON.stringify(getEssentialData(data));
                        const prevEssential = datastoresRef.current ? 
                            JSON.stringify(getEssentialData(datastoresRef.current)) : null;
                        
                        // Only update if structure changed (not just usage percentages)
                        if (currentEssential !== prevEssential || !initialLoadDone.current) {
                            datastoresRef.current = data;
                            setDatastores(data);
                            
                            // Only set expanded nodes on first load
                            if (!initialLoadDone.current) {
                                const expanded = { shared: true };
                                data.nodes?.forEach(n => expanded[n] = true);
                                setExpandedNodes(expanded);
                            }
                        } else {
                            // update usage data without triggering re-render of structure
                            datastoresRef.current = data;
                            setDatastores(data);  // prev => data
                        }
                        
                        initialLoadDone.current = true;
                    }
                } catch (err) {
                    console.error('fetching datastores:', err);
                } finally {
                    setLoading(false);
                    fetchingRef.current = false;
                }
            };
            
            // storage clusters (ceph etc)
            const fetchStorageClusters = async () => {
                try {
                    const r = await authFetch(`${API_URL}/clusters/${clusterId}/storage-clusters`);
                    if (r?.ok) {
                        setStorageClusters(await r.json());
                    }
                } catch (e) {
                    console.error('fetching storage clusters:', e);
                }
            };
            
            const loadClusterStatus = async (scId) => {
                setBalancingLoading(true);
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/storage-clusters/${scId}/status`);
                    if (response && response.ok) {
                        setClusterStatus(await response.json());
                    }
                } catch (error) {
                    console.error('loading cluster status:', error);
                } finally {
                    setBalancingLoading(false);
                }
            };
            
            const createStorageCluster = async () => {
                if (!newClusterName.trim() || newClusterStorages.length < 2) {
                    alert(t('needTwoStorages') || 'Need at least 2 storages');
                    return;
                }
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/storage-clusters`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            name: newClusterName,
                            storages: newClusterStorages,
                            threshold: newClusterThreshold
                        })
                    });
                    if (response && response.ok) {
                        setShowCreateCluster(false);
                        setNewClusterName('');
                        setNewClusterStorages([]);
                        setNewClusterThreshold(20);
                        fetchStorageClusters();
                    } else {
                        const err = await response.json();
                        alert(err.error || 'Failed to create');
                    }
                } catch (error) {
                    console.error('creating storage cluster:', error);
                }
            };
            
            const updateClusterThreshold = (scId, threshold) => {
                // update local state immediately
                setStorageClusters(prev => prev.map(sc => 
                    sc.id === scId ? { ...sc, threshold } : sc
                ));
                if (clusterStatus?.id === scId) {
                    setClusterStatus(prev => prev ? { ...prev, threshold } : null);
                }
                
                // Debounce API call
                if (thresholdTimer.current) clearTimeout(thresholdTimer.current);
                thresholdTimer.current = setTimeout(async () => {
                    try {
                        await authFetch(`${API_URL}/clusters/${clusterId}/storage-clusters/${scId}`, {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ threshold })
                        });
                    } catch (error) {
                        console.error('updating threshold:', error);
                    }
                }, 500);
            };
            
            const toggleClusterEnabled = async (scId, enabled) => {
                try {
                    await authFetch(`${API_URL}/clusters/${clusterId}/storage-clusters/${scId}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ enabled })
                    });
                    setStorageClusters(prev => prev.map(sc => 
                        sc.id === scId ? { ...sc, enabled } : sc
                    ));
                } catch (error) {
                    console.error('toggling cluster:', error);
                }
            };
            
            const toggleAutoBalance = async (scId, auto_balance) => {
                try {
                    await authFetch(`${API_URL}/clusters/${clusterId}/storage-clusters/${scId}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ auto_balance })
                    });
                    setStorageClusters(prev => prev.map(sc => 
                        sc.id === scId ? { ...sc, auto_balance } : sc
                    ));
                } catch (error) {
                    console.error('toggling auto-balance:', error);
                }
            };
            
            const deleteStorageCluster = async (scId) => {
                if (!confirm(t('confirmDeleteCluster') || 'Delete this storage cluster?')) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/storage-clusters/${scId}`, {
                        method: 'DELETE'
                    });
                    if (response && response.ok) {
                        setStorageClusters(prev => prev.filter(sc => sc.id !== scId));
                        if (selectedCluster === scId) {
                            setSelectedCluster(null);
                            setClusterStatus(null);
                        }
                    }
                } catch (error) {
                    console.error('deleting storage cluster:', error);
                }
            };
            
            const addStorageToCluster = async (scId, storageName) => {
                const cluster = storageClusters.find(sc => sc.id === scId);
                if (!cluster) return;
                
                const newStorages = [...cluster.storages, storageName];
                try {
                    await authFetch(`${API_URL}/clusters/${clusterId}/storage-clusters/${scId}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ storages: newStorages })
                    });
                    fetchStorageClusters();
                    if (selectedCluster === scId) loadClusterStatus(scId);
                } catch (error) {
                    console.error('adding storage:', error);
                }
            };
            
            const removeStorageFromCluster = async (scId, storageName) => {
                const cluster = storageClusters.find(sc => sc.id === scId);
                if (!cluster || cluster.storages.length <= 2) {
                    alert(t('minTwoStorages') || 'Minimum 2 storages required');
                    return;
                }
                
                const newStorages = cluster.storages.filter(s => s !== storageName);
                try {
                    await authFetch(`${API_URL}/clusters/${clusterId}/storage-clusters/${scId}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ storages: newStorages })
                    });
                    fetchStorageClusters();
                    if (selectedCluster === scId) loadClusterStatus(scId);
                } catch (error) {
                    console.error('removing storage:', error);
                }
            };
            
            const executeMigration = async (rec) => {
                if (!confirm(`Move ${rec.disk} of ${rec.vm_name} from ${rec.source} to ${rec.target}?`)) return;
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/storage-balancing/migrate`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            vmid: rec.vmid,
                            disk: rec.disk,
                            target: rec.target
                        })
                    });
                    if (response && response.ok) {
                        alert(t('migrationStarted') || 'Migration started!');
                        if (selectedCluster) loadClusterStatus(selectedCluster);
                    } else {
                        const err = await response.json();
                        alert(err.error || 'Migration failed');
                    }
                } catch (error) {
                    console.error('executing migration:', error);
                }
            };
            
            const loadStorageContent = async (storageName, node) => {
                setContentLoading(true);
                setSelectedStorage({ name: storageName, node });
                try {
                    const url = node 
                        ? `${API_URL}/clusters/${clusterId}/datastores/${storageName}/content?node=${node}`
                        : `${API_URL}/clusters/${clusterId}/datastores/${storageName}/content`;
                    const response = await authFetch(url);
                    if (response && response.ok) {
                        setStorageContent(await response.json());
                    }
                } catch (error) {
                    console.error('loading content:', error);
                } finally {
                    setContentLoading(false);
                }
            };
            
            const handleDelete = async (item) => {
                try {
                    const url = `${API_URL}/clusters/${clusterId}/datastores/${selectedStorage.name}/content/${encodeURIComponent(item.volid)}?node=${selectedStorage.node || ''}`;
                    const response = await authFetch(url, { method: 'DELETE' });
                    
                    if (response && response.ok) {
                        setStorageContent(prev => prev.filter(i => i.volid !== item.volid));
                        setDeleteConfirm(null);
                    } else {
                        const err = await response.json();
                        alert(err.error || t('deleteFailed'));
                    }
                } catch (error) {
                    console.error('deleting:', error);
                    alert(t('deleteFailed'));
                }
            };
            
            const handleUpload = async () => {
                if (!uploadFile || !selectedStorage) return;
                
                setUploading(true);
                setUploadProgress(0);
                setUploadSpeed(0);
                
                const formData = new FormData();
                formData.append('file', uploadFile);
                formData.append('content', 'iso');
                if (selectedStorage.node) {
                    formData.append('node', selectedStorage.node);
                }
                
                // Use XMLHttpRequest for progress tracking
                const xhr = new XMLHttpRequest();
                const startTime = Date.now();
                let lastLoaded = 0;
                let lastTime = startTime;
                
                xhr.upload.addEventListener('progress', (e) => {
                    if (e.lengthComputable) {
                        const percent = Math.round((e.loaded / e.total) * 100);
                        setUploadProgress(percent);
                        
                        // calc speed
                        const now = Date.now();
                        const timeDiff = (now - lastTime) / 1000; // seconds
                        if (timeDiff > 0.5) { // update speed every 500ms
                            const bytesDiff = e.loaded - lastLoaded;
                            const speed = bytesDiff / timeDiff; // bytes per second
                            setUploadSpeed(speed);
                            lastLoaded = e.loaded;
                            lastTime = now;
                        }
                    }
                });
                
                xhr.addEventListener('load', () => {
                    if (xhr.status >= 200 && xhr.status < 300) {
                        setUploadModalOpen(false);
                        setUploadFile(null);
                        setUploadProgress(0);
                        setUploadSpeed(0);
                        // refresh after delay
                        setTimeout(() => loadStorageContent(selectedStorage.name, selectedStorage.node), 2000);
                    } else {
                        try {
                            const err = JSON.parse(xhr.responseText);
                            alert(err.error || t('uploadFailed'));
                        } catch {
                            alert(t('uploadFailed'));
                        }
                    }
                    setUploading(false);
                });
                
                xhr.addEventListener('error', () => {
                    console.error('Upload error');
                    alert(t('uploadFailedNetwork'));
                    setUploading(false);
                    setUploadProgress(0);
                    setUploadSpeed(0);
                });
                
                xhr.addEventListener('abort', () => {
                    setUploading(false);
                    setUploadProgress(0);
                    setUploadSpeed(0);
                });
                
                xhr.open('POST', `${API_URL}/clusters/${clusterId}/datastores/${selectedStorage.name}/upload`);
                
                // auth headers
                const headers = getAuthHeaders();
                for (const [key, value] of Object.entries(headers)) {
                    xhr.setRequestHeader(key, value);
                }
                
                xhr.send(formData);
            };
            
            const formatSpeed = (bytesPerSec) => {
                if (!bytesPerSec) return '0 B/s';
                const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
                let i = 0;
                while (bytesPerSec >= 1024 && i < units.length - 1) { 
                    bytesPerSec /= 1024; 
                    i++; 
                }
                return `${bytesPerSec.toFixed(1)} ${units[i]}`;
            };
            
            // NS: Download ISO from URL - Jan 2026 (like Proxmox)
            const handleDownloadFromUrl = async () => {
                if (!downloadUrl || !selectedStorage) return;
                
                // Extract filename from URL if not provided
                let filename = downloadFilename.trim();
                if (!filename) {
                    try {
                        const urlPath = new URL(downloadUrl).pathname;
                        filename = urlPath.split('/').pop() || 'download.iso';
                    } catch {
                        filename = 'download.iso';
                    }
                }
                
                // Ensure .iso extension
                if (!filename.toLowerCase().endsWith('.iso') && !filename.toLowerCase().endsWith('.img')) {
                    filename += '.iso';
                }
                
                setUrlDownloading(true);
                setUrlDownloadProgress({ status: 'starting', percent: 0, message: t('startingDownload') || 'Starting download...' });
                
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/datastores/${selectedStorage.name}/download-url`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            url: downloadUrl,
                            filename: filename,
                            node: selectedStorage.node || ''
                        })
                    });
                    
                    if (response && response.ok) {
                        const data = await response.json();
                        const taskId = data.task_id;
                        
                        // Poll for progress
                        const pollInterval = setInterval(async () => {
                            try {
                                const statusResp = await authFetch(`${API_URL}/clusters/${clusterId}/datastores/${selectedStorage.name}/download-status/${taskId}`);
                                if (statusResp && statusResp.ok) {
                                    const status = await statusResp.json();
                                    setUrlDownloadProgress(status);
                                    
                                    if (status.status === 'completed') {
                                        clearInterval(pollInterval);
                                        setUrlDownloading(false);
                                        setDownloadUrlModalOpen(false);
                                        setDownloadUrl('');
                                        setDownloadFilename('');
                                        // Refresh content
                                        setTimeout(() => loadStorageContent(selectedStorage.name, selectedStorage.node), 1000);
                                    } else if (status.status === 'error') {
                                        clearInterval(pollInterval);
                                        setUrlDownloading(false);
                                        alert(status.message || t('downloadFailed') || 'Download failed');
                                    }
                                }
                            } catch (e) {
                                console.error('Polling download status:', e);
                            }
                        }, 1000);
                        
                        // Cleanup after 30 min max
                        setTimeout(() => clearInterval(pollInterval), 30 * 60 * 1000);
                        
                    } else {
                        const err = await response.json();
                        alert(err.error || t('downloadFailed') || 'Download failed');
                        setUrlDownloading(false);
                    }
                } catch (error) {
                    console.error('Download from URL error:', error);
                    alert(t('downloadFailed') || 'Download failed');
                    setUrlDownloading(false);
                }
            };
            
            // NS: ESXi Integration functions - Dec 2025
            const fetchEsxiHosts = async () => {
                try {
                    const r = await authFetch(`${API_URL}/clusters/${clusterId}/esxi-hosts`);
                    if (r?.ok) setEsxiHosts(await r.json());
                } catch (e) {
                    console.error('fetching esxi hosts:', e);
                }
            };
            
            const connectEsxiHost = async () => {
                if (!esxiForm.host || !esxiForm.password) {
                    alert(t('fillAllFields') || 'Please fill all fields');
                    return;
                }
                setEsxiLoading(true);
                try {
                    const r = await authFetch(`${API_URL}/clusters/${clusterId}/esxi-hosts`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(esxiForm)
                    });
                    if (r?.ok) {
                        setShowAddEsxi(false);
                        setEsxiForm({ host: '', username: 'root', password: '' });
                        fetchEsxiHosts();
                    } else {
                        const err = await r.json();
                        alert(err.error || t('connectionFailed'));
                    }
                } catch (e) {
                    alert(t('connectionFailed'));
                } finally {
                    setEsxiLoading(false);
                }
            };
            
            const disconnectEsxiHost = async (hostId) => {
                if (!confirm(t('confirmDisconnect') || 'Disconnect this ESXi host?')) return;
                try {
                    const r = await authFetch(`${API_URL}/clusters/${clusterId}/esxi-hosts/${hostId}`, {
                        method: 'DELETE'
                    });
                    if (r?.ok) {
                        setEsxiHosts(prev => prev.filter(h => h.id !== hostId));
                        if (selectedEsxi === hostId) {
                            setSelectedEsxi(null);
                            setEsxiVms([]);
                        }
                    }
                } catch (e) {
                    console.error('disconnecting esxi:', e);
                }
            };
            
            const fetchEsxiVms = async (hostId) => {
                setSelectedEsxi(hostId);
                setEsxiVmsLoading(true);
                try {
                    const r = await authFetch(`${API_URL}/clusters/${clusterId}/esxi-hosts/${hostId}/vms`);
                    if (r?.ok) setEsxiVms(await r.json());
                } catch (e) {
                    console.error('fetching esxi vms:', e);
                } finally {
                    setEsxiVmsLoading(false);
                }
            };
            
            // NS: ESXi VMs should be migrated via VMware Migration Wizard (Tasks tab)
            // The native Proxmox import was removed - our wizard handles hardware detection better
            
            // load esxi hosts on mount
            useEffect(() => {
                fetchEsxiHosts();
            }, [clusterId]);
            
            const toggleNode = (nodeKey) => {
                setExpandedNodes(prev => ({ ...prev, [nodeKey]: !prev[nodeKey] }));
            };
            
            const formatSize = (bytes) => {
                if (!bytes) return '0 B';
                const units = ['B', 'KB', 'MB', 'GB', 'TB'];
                let i = 0;
                while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
                return `${bytes.toFixed(1)} ${units[i]}`;
            };
            
            const getContentIcon = (content) => {
                if (content?.includes('iso')) return '💿';
                if (content?.includes('images') || content?.includes('rootdir')) return '💾';
                if (content?.includes('backup')) return '📦';
                if (content?.includes('vztmpl')) return '📋';
                return '📁';
            };
            
            const getTypeColor = (type) => {
                const colors = {
                    'zfspool': 'text-blue-400', 'lvmthin': 'text-purple-400', 'lvm': 'text-purple-400',
                    'dir': 'text-green-400', 'nfs': 'text-yellow-400', 'cifs': 'text-yellow-400',
                    'cephfs': 'text-red-400', 'rbd': 'text-red-400',
                };
                return colors[type] || 'text-gray-400';
            };
            
            const canUploadTo = (storage) => {
                return storage?.content?.includes('iso') || storage?.content?.includes('vztmpl');
            };
            
            if (loading) {
                return (
                    <div className="flex items-center justify-center py-12">
                        <Icons.RotateCw className="animate-spin" />
                        <span className="ml-2">{t('loading')}</span>
                    </div>
                );
            }
            
            const StorageRow = ({ storage, node, isShared }) => {
                const usedPercent = storage.total ? (storage.used / storage.total * 100) : 0;
                const isSelected = selectedStorage?.name === storage.storage && selectedStorage?.node === node;
                
                return (
                    <div 
                        className={`flex items-center justify-between p-3 rounded-lg cursor-pointer transition-all ${
                            isSelected ? 'bg-proxmox-orange/20 border border-proxmox-orange/50' : 'bg-proxmox-dark hover:bg-proxmox-hover'
                        }`}
                        onClick={() => loadStorageContent(storage.storage, node)}
                    >
                        <div className="flex items-center gap-3">
                            <span className="text-lg">{getContentIcon(storage.content)}</span>
                            <div>
                                <div className="font-medium text-white">{storage.storage}</div>
                                <div className="text-xs text-gray-500">
                                    <span className={getTypeColor(storage.type)}>{storage.type}</span>
                                </div>
                            </div>
                        </div>
                        <div className="text-right">
                            <div className="text-sm text-white">{formatSize(storage.used)} / {formatSize(storage.total)}</div>
                            <div className="w-24 h-1.5 bg-proxmox-border rounded-full mt-1">
                                <div 
                                    className={`h-full rounded-full ${usedPercent > 90 ? 'bg-red-500' : usedPercent > 70 ? 'bg-yellow-500' : 'bg-green-500'}`}
                                    style={{ width: `${Math.min(usedPercent, 100)}%` }}
                                />
                            </div>
                        </div>
                    </div>
                );
            };
            
            return (
                <div className="space-y-4">
                    {/* Tab Switcher */}
                    <div className="flex gap-2">
                        <button
                            onClick={() => setActiveTab('browse')}
                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                                activeTab === 'browse' ? 'bg-proxmox-orange text-white' : 'bg-proxmox-card text-gray-400 hover:text-white'
                            }`}
                        >
                            <Icons.Folder className="inline mr-2" />
                            {t('browse') || 'Browse'}
                        </button>
                        <button
                            onClick={() => { setActiveTab('balancing'); fetchStorageClusters(); }}
                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                                activeTab === 'balancing' ? 'bg-proxmox-orange text-white' : 'bg-proxmox-card text-gray-400 hover:text-white'
                            }`}
                        >
                            <Icons.Zap className="inline mr-2" />
                            Storage Balancing
                        </button>
                    </div>
                    
                    {activeTab === 'browse' ? (
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                            {/* Storage Tree */}
                            <div className="lg:col-span-1 bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                <div className="p-4 border-b border-proxmox-border bg-proxmox-dark">
                                    <h3 className="font-semibold flex items-center gap-2">
                                        <Icons.Database />
                                        {t('datastores') || 'Datastores'}
                                    </h3>
                                </div>
                                <div className="p-4 space-y-4 max-h-[600px] overflow-y-auto">
                                    {/* Shared Storage */}
                                    {datastores.shared?.length > 0 && (
                                        <div>
                                            <button 
                                                className="flex items-center gap-2 w-full text-left p-2 rounded-lg hover:bg-proxmox-hover"
                                                onClick={() => toggleNode('shared')}
                                            >
                                                <span className={`transform transition-transform ${expandedNodes.shared ? 'rotate-90' : ''}`}>▶</span>
                                                <Icons.Globe />
                                                <span className="font-medium text-yellow-400">{t('sharedStorage') || 'Shared Storage'}</span>
                                                <span className="text-xs text-gray-500 ml-auto">{datastores.shared.length}</span>
                                            </button>
                                            {expandedNodes.shared && (
                                                <div className="ml-6 mt-2 space-y-2">
                                                    {datastores.shared.map(storage => (
                                                        <StorageRow key={storage.storage} storage={storage} isShared={true} />
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    )}
                                    
                                    {/* Local Storage per Node */}
                                    {datastores.nodes?.map(node => (
                                        <div key={node}>
                                            <button 
                                                className="flex items-center gap-2 w-full text-left p-2 rounded-lg hover:bg-proxmox-hover"
                                                onClick={() => toggleNode(node)}
                                            >
                                                <span className={`transform transition-transform ${expandedNodes[node] ? 'rotate-90' : ''}`}>▶</span>
                                                <Icons.Server />
                                                <span className="font-medium">{node}</span>
                                                <span className="text-xs text-gray-500 ml-auto">{datastores.local[node]?.length || 0}</span>
                                            </button>
                                            {expandedNodes[node] && datastores.local[node] && (
                                                <div className="ml-6 mt-2 space-y-2">
                                                    {datastores.local[node].map(storage => (
                                                        <StorageRow key={`${node}-${storage.storage}`} storage={storage} node={node} />
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                    
                                    {/* NS: ESXi Hosts Section - Dec 2025 */}
                                    <div className="mt-4 pt-4 border-t border-proxmox-border">
                                        <div className="flex items-center justify-between mb-2">
                                            <button 
                                                className="flex items-center gap-2 text-left p-2 rounded-lg hover:bg-proxmox-hover flex-1"
                                                onClick={() => toggleNode('esxi')}
                                            >
                                                <span className={`transform transition-transform ${expandedNodes.esxi ? 'rotate-90' : ''}`}>▶</span>
                                                <span className="text-lg">🖥️</span>
                                                <span className="font-medium text-cyan-400">{t('esxiHosts') || 'ESXi Hosts'}</span>
                                                <span className="text-xs text-gray-500 ml-auto">{esxiHosts.length}</span>
                                            </button>
                                            {isAdmin && (
                                                <button
                                                    onClick={() => setShowAddEsxi(true)}
                                                    className="p-1.5 hover:bg-proxmox-hover rounded-lg text-gray-400 hover:text-cyan-400"
                                                    title={t('connectEsxi') || 'Connect ESXi'}
                                                >
                                                    <Icons.Plus />
                                                </button>
                                            )}
                                        </div>
                                        {expandedNodes.esxi && (
                                            <div className="ml-6 space-y-2">
                                                {esxiHosts.length === 0 ? (
                                                    <p className="text-xs text-gray-500 py-2">{t('noEsxiHosts') || 'No ESXi hosts connected'}</p>
                                                ) : (
                                                    esxiHosts.map(host => (
                                                        <div 
                                                            key={host.id}
                                                            className={`flex items-center gap-2 p-2 rounded-lg cursor-pointer transition-colors ${
                                                                selectedEsxi === host.id ? 'bg-cyan-500/20 border border-cyan-500/30' : 'hover:bg-proxmox-hover'
                                                            }`}
                                                            onClick={() => fetchEsxiVms(host.id)}
                                                        >
                                                            <span className={`w-2 h-2 rounded-full ${host.connected ? 'bg-green-500' : 'bg-red-500'}`} />
                                                            <span className="text-sm">{host.host}</span>
                                                            {isAdmin && (
                                                                <button
                                                                    onClick={(e) => { e.stopPropagation(); disconnectEsxiHost(host.id); }}
                                                                    className="ml-auto p-1 hover:bg-red-500/20 rounded text-gray-500 hover:text-red-400"
                                                                    title={t('esxiDisconnect')}
                                                                >
                                                                    <Icons.X className="w-3 h-3" />
                                                                </button>
                                                            )}
                                                        </div>
                                                    ))
                                                )}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                            
                            {/* Storage Content / ESXi VMs Panel */}
                            <div className="lg:col-span-2 bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                {selectedEsxi ? (
                                    /* LW: ESXi VMs Panel */
                                    <>
                                        <div className="p-4 border-b border-proxmox-border bg-proxmox-dark flex justify-between items-center">
                                            <h3 className="font-semibold flex items-center gap-2">
                                                <span className="text-lg">🖥️</span>
                                                {t('esxiVms') || 'ESXi VMs'}
                                                <span className="text-xs text-gray-500">({esxiHosts.find(h => h.id === selectedEsxi)?.host})</span>
                                            </h3>
                                            <button
                                                onClick={() => { setSelectedEsxi(null); setEsxiVms([]); }}
                                                className="p-1.5 hover:bg-proxmox-hover rounded-lg text-gray-400"
                                            >
                                                <Icons.X />
                                            </button>
                                        </div>
                                        <div className="p-4">
                                            {/* Experimental hint */}
                                            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg mb-4 flex items-center gap-2">
                                                <span>🧪</span>
                                                <span className="text-xs text-cyan-400">{t('esxiExperimental') || 'ESXi integration is experimental'}</span>
                                            </div>
                                            
                                            {esxiVmsLoading ? (
                                                <div className="flex items-center justify-center py-12">
                                                    <Icons.RotateCw className="animate-spin" />
                                                </div>
                                            ) : esxiVms.length === 0 ? (
                                                <div className="text-center py-12 text-gray-500">
                                                    <p>{t('esxiNoVms') || 'No VMs on this ESXi host'}</p>
                                                </div>
                                            ) : (
                                                <div className="space-y-2">
                                                    {esxiVms.map(vm => (
                                                        <div key={vm.id} className="p-3 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                            <div className="flex items-center justify-between">
                                                                <div className="flex items-center gap-3">
                                                                    <span className="w-3 h-3 rounded-full bg-gray-500" />
                                                                    <div>
                                                                        <p className="font-medium text-white">{vm.name}</p>
                                                                        <p className="text-xs text-gray-500">
                                                                            {vm.guest_os !== 'Unknown' ? `${vm.guest_os} • ` : ''}
                                                                            {vm.num_cpu > 0 ? `${vm.num_cpu} vCPU • ` : ''}
                                                                            {vm.memory_mb > 0 ? `${Math.round(vm.memory_mb / 1024)} GB RAM` : ''}
                                                                        </p>
                                                                        {/* LW: show volid for debugging */}
                                                                        <p className="text-xs text-gray-600 font-mono truncate max-w-xs">{vm.volid || vm.id}</p>
                                                                    </div>
                                                                </div>
                                                                <div className="flex items-center gap-2">
                                                                    <span className="text-xs text-gray-500 italic">
                                                                        {t('useVMwareMigration') || 'Use ESXi → Migration Wizard'}
                                                                    </span>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    </>
                                ) : (
                                    /* Original Storage Content */
                                    <>
                                        <div className="p-4 border-b border-proxmox-border bg-proxmox-dark flex justify-between items-center">
                                            <h3 className="font-semibold flex items-center gap-2">
                                                <Icons.Folder />
                                                {selectedStorage ? (
                                                    <>{t('content') || 'Content'}: {selectedStorage.name}</>
                                                ) : (
                                                    t('selectStorage') || 'Select a storage'
                                                )}
                                            </h3>
                                            {selectedStorage && isAdmin && (
                                                <div className="flex gap-2">
                                                    {/* NS: Download Templates button - only for vztmpl storage */}
                                                    {(() => {
                                                        const storage = datastores.shared.find(s => s.storage === selectedStorage.name) || 
                                                                       datastores.local[selectedStorage.node]?.find(s => s.storage === selectedStorage.name);
                                                        return storage?.content?.includes('vztmpl');
                                                    })() && (
                                                        <button
                                                            onClick={() => { setShowTemplateModal(true); loadAvailableTemplates(); }}
                                                            className="flex items-center gap-1 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm"
                                                        >
                                                            <Icons.Download /> Templates
                                                        </button>
                                                    )}
                                                    {/* NS: Download from URL - for ISO storage (like Proxmox) */}
                                                    {(() => {
                                                        const storage = datastores.shared.find(s => s.storage === selectedStorage.name) || 
                                                                       datastores.local[selectedStorage.node]?.find(s => s.storage === selectedStorage.name);
                                                        return storage?.content?.includes('iso');
                                                    })() && (
                                                        <button
                                                            onClick={() => setDownloadUrlModalOpen(true)}
                                                            className="flex items-center gap-1 px-3 py-1.5 bg-green-600 hover:bg-green-700 rounded-lg text-sm"
                                                            title={t('downloadFromUrl') || 'Download from URL'}
                                                        >
                                                            <Icons.Link /> {t('fromUrl') || 'From URL'}
                                                        </button>
                                                    )}
                                                    {canUploadTo(datastores.shared.find(s => s.storage === selectedStorage.name) || 
                                                                 datastores.local[selectedStorage.node]?.find(s => s.storage === selectedStorage.name)) && (
                                                        <button
                                                            onClick={() => setUploadModalOpen(true)}
                                                            className="flex items-center gap-1 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                                        >
                                                            <Icons.Upload /> {t('upload') || 'Upload'}
                                                        </button>
                                                    )}
                                                    {/* NS: Rescan button for iSCSI/LVM storage - Feb 2026 */}
                                                    {(() => {
                                                        const storage = datastores.shared.find(s => s.storage === selectedStorage.name) || 
                                                                       datastores.local[selectedStorage.node]?.find(s => s.storage === selectedStorage.name);
                                                        return ['iscsi', 'iscsidirect', 'lvm', 'lvmthin', 'zfspool', 'zfs'].includes(storage?.type);
                                                    })() && (
                                                        <button
                                                            onClick={() => setShowRescanModal(true)}
                                                            className="flex items-center gap-1 px-3 py-1.5 bg-purple-600 hover:bg-purple-700 rounded-lg text-sm"
                                                            title={t('rescanStorageTooltip') || 'Rescan storage to detect new LUNs/volumes'}
                                                        >
                                                            <Icons.RefreshCw className="w-4 h-4" /> {t('rescan') || 'Rescan'}
                                                        </button>
                                                    )}
                                                    <button
                                                        onClick={() => loadStorageContent(selectedStorage.name, selectedStorage.node)}
                                                        className="p-1.5 hover:bg-proxmox-hover rounded-lg text-gray-400 hover:text-white"
                                                    >
                                                        <Icons.RotateCw />
                                                    </button>
                                                </div>
                                            )}
                                        </div>
                                        <div className="p-4">
                                            {contentLoading ? (
                                                <div className="flex items-center justify-center py-12">
                                                    <Icons.RotateCw className="animate-spin" />
                                                </div>
                                            ) : !selectedStorage ? (
                                                <div className="text-center py-12 text-gray-500">
                                                    <Icons.Database className="mx-auto mb-2 opacity-50" />
                                                    <p>{t('clickStorageToView') || 'Click on a storage to view its contents'}</p>
                                                </div>
                                            ) : storageContent.length === 0 ? (
                                                <div className="text-center py-12 text-gray-500">
                                                    <Icons.Folder className="mx-auto mb-2 opacity-50" />
                                                    <p>{t('storageEmpty') || 'This storage is empty'}</p>
                                                </div>
                                            ) : (
                                                <div className="space-y-1 max-h-[500px] overflow-y-auto">
                                                    <table className="w-full">
                                                        <thead className="sticky top-0 bg-proxmox-card">
                                                            <tr className="text-left text-xs text-gray-500 uppercase">
                                                                <th className="p-2">{t('name') || 'Name'}</th>
                                                                <th className="p-2">{t('type') || 'Type'}</th>
                                                                <th className="p-2">{t('format') || 'Format'}</th>
                                                        <th className="p-2 text-right">{t('size') || 'Size'}</th>
                                                        {isAdmin && <th className="p-2 w-10"></th>}
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {storageContent.map((item, idx) => (
                                                        <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-hover">
                                                            <td className="p-2">
                                                                <div className="flex items-center gap-2">
                                                                    <span>{item.content === 'iso' ? '💿' : item.content === 'backup' ? '📦' : '💾'}</span>
                                                                    <span className="font-mono text-sm truncate max-w-xs" title={item.volid}>
                                                                        {item.volid?.split('/').pop() || item.volid}
                                                                    </span>
                                                                    {item.vmid && (
                                                                        <span className="text-xs text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded">
                                                                            VM {item.vmid}
                                                                        </span>
                                                                    )}
                                                                </div>
                                                            </td>
                                                            <td className="p-2 text-sm text-gray-400">{item.content}</td>
                                                            <td className="p-2 text-sm text-gray-400">{item.format || '-'}</td>
                                                            <td className="p-2 text-sm text-right">{item.size_human || formatSize(item.size)}</td>
                                                            {isAdmin && (
                                                                <td className="p-2">
                                                                    {/* LW: allow deleting backups even with vmid - vzdumps always have vmid attached */}
                                                                    {(item.content === 'backup' || (!item.vmid && (item.content === 'iso' || item.content === 'vztmpl'))) && (
                                                                        <button
                                                                            onClick={() => setDeleteConfirm(item)}
                                                                            className="p-1 hover:bg-red-500/20 rounded text-gray-500 hover:text-red-400"
                                                                            title={t('delete') || 'Delete'}
                                                                        >
                                                                            <Icons.Trash />
                                                                        </button>
                                                                    )}
                                                                </td>
                                                            )}
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    )}
                                </div>
                            </>
                        )}
                    </div>
                </div>
            ) : (
                /* Storage Balancing Tab with Storage Clusters */
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Experimental warning */}
                    <div className="lg:col-span-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-xl flex items-center gap-3">
                        <span className="text-2xl">🧪</span>
                        <div>
                            <p className="text-yellow-400 font-medium">{t('experimentalFeature') || 'Experimental Feature'}</p>
                            <p className="text-yellow-300/70 text-sm">{t('storageBalancingExperimental') || 'Storage Balancing is still experimental. We appreciate your feedback!'}</p>
                        </div>
                    </div>
                    
                    {/* Storage Clusters List */}
                            <div className="lg:col-span-1 bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                <div className="p-4 border-b border-proxmox-border bg-proxmox-dark flex justify-between items-center">
                                    <h3 className="font-semibold flex items-center gap-2">
                                        <Icons.Zap className="text-yellow-400" />
                                        Storage Clusters
                                    </h3>
                                    {isAdmin && (
                                        <button
                                            onClick={() => setShowCreateCluster(true)}
                                            className="p-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg"
                                            title={t('createCluster') || 'Create Cluster'}
                                        >
                                            <Icons.Plus />
                                        </button>
                                    )}
                                </div>
                                <div className="p-4 space-y-3 max-h-[500px] overflow-y-auto">
                                    {storageClusters.length === 0 ? (
                                        <div className="text-center py-8 text-gray-500">
                                            <Icons.Database className="mx-auto mb-2 opacity-50" />
                                            <p>{t('noStorageClusters') || 'No storage clusters configured'}</p>
                                            <p className="text-xs mt-1">{t('createStorageClusterHint') || 'Create a cluster to balance storage across multiple volumes'}</p>
                                        </div>
                                    ) : (
                                        storageClusters.map(sc => (
                                            <div 
                                                key={sc.id}
                                                className={`p-3 rounded-lg cursor-pointer transition-all ${
                                                    selectedCluster === sc.id 
                                                        ? 'bg-proxmox-orange/20 border border-proxmox-orange/50' 
                                                        : 'bg-proxmox-dark hover:bg-proxmox-hover'
                                                }`}
                                                onClick={() => { setSelectedCluster(sc.id); loadClusterStatus(sc.id); }}
                                            >
                                                <div className="flex items-center justify-between">
                                                    <div className="flex items-center gap-2">
                                                        <span className={`w-2 h-2 rounded-full ${sc.enabled ? 'bg-green-500' : 'bg-gray-500'}`} />
                                                        <span className="font-medium">{sc.name}</span>
                                                    </div>
                                                    {isAdmin && (
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); deleteStorageCluster(sc.id); }}
                                                            className="p-1 hover:bg-red-500/20 rounded text-gray-500 hover:text-red-400"
                                                        >
                                                            <Icons.Trash />
                                                        </button>
                                                    )}
                                                </div>
                                                <div className="text-xs text-gray-500 mt-1">
                                                    {sc.storages?.length || 0} {t('storages') || 'storages'} • {t('threshold')}: {sc.threshold}%
                                                </div>
                                            </div>
                                        ))
                                    )}
                                </div>
                            </div>
                            
                            {/* Storage Cluster Details */}
                            <div className="lg:col-span-2 bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                <div className="p-4 border-b border-proxmox-border bg-proxmox-dark">
                                    <h3 className="font-semibold">
                                        {clusterStatus ? clusterStatus.name : (t('selectCluster') || 'Select a storage cluster')}
                                    </h3>
                                </div>
                                <div className="p-4">
                                    {balancingLoading ? (
                                        <div className="flex items-center justify-center py-12">
                                            <Icons.RotateCw className="animate-spin" />
                                        </div>
                                    ) : !clusterStatus ? (
                                        <div className="text-center py-12 text-gray-500">
                                            <Icons.Zap className="mx-auto mb-2 opacity-50" />
                                            <p>{t('selectClusterToView') || 'Select a storage cluster to view balancing status'}</p>
                                        </div>
                                    ) : (
                                        <div className="space-y-6">
                                            {/* Cluster Settings */}
                                            <div className="flex items-center justify-between gap-4 p-4 bg-proxmox-dark rounded-lg flex-wrap">
                                                <Toggle
                                                    checked={clusterStatus.enabled}
                                                    onChange={(v) => toggleClusterEnabled(clusterStatus.id, v)}
                                                    label={t('enabled') || 'Enabled'}
                                                />
                                                <div className="flex items-center gap-4">
                                                    <Toggle
                                                        checked={storageClusters.find(sc => sc.id === clusterStatus.id)?.auto_balance || false}
                                                        onChange={(v) => toggleAutoBalance(clusterStatus.id, v)}
                                                        label={t('autoBalance') || 'Auto-Balance'}
                                                    />
                                                    <button
                                                        onClick={() => loadClusterStatus(clusterStatus.id)}
                                                        className="p-2 hover:bg-proxmox-hover rounded-lg text-gray-400 hover:text-white"
                                                    >
                                                        <Icons.RotateCw />
                                                    </button>
                                                </div>
                                            </div>
                                            
                                            {/* Auto-Balance Info */}
                                            {storageClusters.find(sc => sc.id === clusterStatus.id)?.auto_balance && (
                                                <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
                                                    <div className="flex items-center gap-2 text-green-400 mb-2">
                                                        <Icons.Zap />
                                                        <span className="font-medium">{t('autoBalanceActive') || 'Auto-Balance Active'}</span>
                                                    </div>
                                                    <p className="text-sm text-gray-400">
                                                        {t('autoBalanceDesc') || 'Disks will be automatically migrated when imbalance exceeds threshold. VMs with active snapshots/backups are skipped.'}
                                                    </p>
                                                </div>
                                            )}
                                            
                                            {/* Threshold Slider */}
                                            <div className="p-4 bg-proxmox-dark rounded-lg">
                                                <Slider
                                                    label={t('balancingThreshold') || 'Balancing Threshold'}
                                                    description={t('thresholdDesc') || 'Trigger balancing when imbalance exceeds this value'}
                                                    value={clusterStatus.threshold}
                                                    onChange={(v) => updateClusterThreshold(clusterStatus.id, v)}
                                                    min={5}
                                                    max={50}
                                                    step={5}
                                                />
                                            </div>
                                            
                                            {/* Imbalance Status */}
                                            <div className="flex items-center gap-4 p-4 bg-proxmox-dark rounded-lg">
                                                <div className="flex-1">
                                                    <div className="text-sm text-gray-400">{t('currentImbalance') || 'Current Imbalance'}</div>
                                                    <div className={`text-2xl font-bold ${clusterStatus.imbalance > clusterStatus.threshold ? 'text-yellow-400' : 'text-green-400'}`}>
                                                        {clusterStatus.imbalance}%
                                                    </div>
                                                </div>
                                                <div className={`px-4 py-2 rounded-lg ${clusterStatus.imbalance > clusterStatus.threshold ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'}`}>
                                                    {clusterStatus.imbalance > clusterStatus.threshold ? '⚠️ ' + (t('actionRecommended') || 'Action Recommended') : '✓ ' + (t('balanced') || 'Balanced')}
                                                </div>
                                            </div>
                                            
                                            {/* Storages in Cluster */}
                                            <div>
                                                <div className="flex items-center justify-between mb-3">
                                                    <h4 className="text-sm font-medium text-gray-400">{t('storagesInCluster') || 'Storages in Cluster'}</h4>
                                                    {isAdmin && datastores.shared?.length > (clusterStatus.storages?.length || 0) && (
                                                        <select
                                                            className="px-2 py-1 bg-proxmox-dark border border-proxmox-border rounded text-sm"
                                                            onChange={(e) => { if (e.target.value) { addStorageToCluster(clusterStatus.id, e.target.value); e.target.value = ''; }}}
                                                            defaultValue=""
                                                        >
                                                            <option value="">{t('addStorage') || '+ Add Storage'}</option>
                                                            {datastores.shared?.filter(s => !clusterStatus.storages?.some(cs => cs.storage === s.storage)).map(s => (
                                                                <option key={s.storage} value={s.storage}>{s.storage}</option>
                                                            ))}
                                                        </select>
                                                    )}
                                                </div>
                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                                    {clusterStatus.storages?.map(storage => (
                                                        <div key={storage.storage} className="p-3 bg-proxmox-dark rounded-lg">
                                                            <div className="flex justify-between items-center mb-2">
                                                                <span className="font-medium">{storage.storage}</span>
                                                                <div className="flex items-center gap-2">
                                                                    <span className={`text-sm ${storage.usage_percent > 90 ? 'text-red-400' : storage.usage_percent > 70 ? 'text-yellow-400' : 'text-green-400'}`}>
                                                                        {storage.usage_percent}%
                                                                    </span>
                                                                    {isAdmin && clusterStatus.storages.length > 2 && (
                                                                        <button
                                                                            onClick={() => removeStorageFromCluster(clusterStatus.id, storage.storage)}
                                                                            className="p-1 hover:bg-red-500/20 rounded text-gray-500 hover:text-red-400"
                                                                            title={t('remove') || 'Remove'}
                                                                        >
                                                                            <Icons.X />
                                                                        </button>
                                                                    )}
                                                                </div>
                                                            </div>
                                                            <div className="w-full h-2 bg-proxmox-border rounded-full">
                                                                <div 
                                                                    className={`h-full rounded-full ${storage.usage_percent > 90 ? 'bg-red-500' : storage.usage_percent > 70 ? 'bg-yellow-500' : 'bg-green-500'}`}
                                                                    style={{ width: `${storage.usage_percent}%` }}
                                                                />
                                                            </div>
                                                            <div className="text-xs text-gray-500 mt-1">
                                                                {formatSize(storage.used)} / {formatSize(storage.total)}
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                            
                                            {/* Recommendations */}
                                            {clusterStatus.recommendations?.length > 0 && (
                                                <div>
                                                    <h4 className="text-sm font-medium text-gray-400 mb-3">{t('recommendations') || 'Recommendations'}</h4>
                                                    <div className="space-y-2">
                                                        {clusterStatus.recommendations.map((rec, idx) => (
                                                            <div key={idx} className="flex items-center justify-between p-3 bg-proxmox-dark rounded-lg">
                                                                <div className="flex items-center gap-3">
                                                                    <div className={`p-2 rounded-lg ${rec.vm_status === 'running' ? 'bg-green-500/20' : 'bg-gray-500/20'}`}>
                                                                        <Icons.HardDrive />
                                                                    </div>
                                                                    <div>
                                                                        <div className="font-medium">{rec.vm_name} <span className="text-gray-500">({rec.disk})</span></div>
                                                                        <div className="text-xs text-gray-500">{rec.reason}</div>
                                                                    </div>
                                                                </div>
                                                                {isAdmin && (
                                                                    <button
                                                                        onClick={() => executeMigration(rec)}
                                                                        className="px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                                                    >
                                                                        {t('migrate') || 'Migrate'}
                                                                    </button>
                                                                )}
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                            
                                            {clusterStatus.recommendations?.length === 0 && clusterStatus.imbalance <= clusterStatus.threshold && (
                                                <div className="text-center py-6 text-gray-500">
                                                    <Icons.Check className="mx-auto mb-2 text-green-400" />
                                                    <p>{t('storageBalanced') || 'Storage is well balanced. No action needed.'}</p>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Create Storage Cluster Modal */}
                    {showCreateCluster && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 w-full max-w-lg">
                                <h3 className="text-lg font-semibold mb-4">{t('createStorageCluster') || 'Create Storage Cluster'}</h3>
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-2">{t('clusterName') || 'Cluster Name'}</label>
                                        <input
                                            type="text"
                                            value={newClusterName}
                                            onChange={(e) => setNewClusterName(e.target.value)}
                                            placeholder="e.g. Production Storage"
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-2">{t('selectStorages') || 'Select Storages'} ({t('minTwo') || 'min. 2'})</label>
                                        <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto p-2 bg-proxmox-dark rounded-lg">
                                            {datastores.shared?.map(storage => (
                                                <label key={storage.storage} className="flex items-center gap-2 p-2 hover:bg-proxmox-hover rounded cursor-pointer">
                                                    <input
                                                        type="checkbox"
                                                        checked={newClusterStorages.includes(storage.storage)}
                                                        onChange={(e) => {
                                                            if (e.target.checked) {
                                                                setNewClusterStorages(prev => [...prev, storage.storage]);
                                                            } else {
                                                                setNewClusterStorages(prev => prev.filter(s => s !== storage.storage));
                                                            }
                                                        }}
                                                        className="rounded"
                                                    />
                                                    <span>{storage.storage}</span>
                                                </label>
                                            ))}
                                        </div>
                                        {datastores.shared?.length === 0 && (
                                            <div className="text-center py-4 text-gray-500 text-sm">
                                                {t('noSharedStorages') || 'No shared storages available'}
                                            </div>
                                        )}
                                    </div>
                                    <div>
                                        <Slider
                                            label={t('balancingThreshold') || 'Balancing Threshold'}
                                            value={newClusterThreshold}
                                            onChange={setNewClusterThreshold}
                                            min={5}
                                            max={50}
                                            step={5}
                                        />
                                    </div>
                                    <div className="flex gap-2 justify-end pt-4">
                                        <button
                                            onClick={() => { setShowCreateCluster(false); setNewClusterName(''); setNewClusterStorages([]); }}
                                            className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg"
                                        >
                                            {t('cancel') || 'Cancel'}
                                        </button>
                                        <button
                                            onClick={createStorageCluster}
                                            disabled={!newClusterName.trim() || newClusterStorages.length < 2}
                                            className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg disabled:opacity-50"
                                        >
                                            {t('create') || 'Create'}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Template downloads */}
                    {showTemplateModal && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-4xl max-h-[85vh] flex flex-col">
                                <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                    <h3 className="text-lg font-semibold flex items-center gap-2">
                                        <Icons.Download />
                                        {t('downloadTemplates') || 'Download Container Templates'}
                                    </h3>
                                    <button
                                        onClick={() => setShowTemplateModal(false)}
                                        className="p-1.5 hover:bg-proxmox-hover rounded-lg text-gray-400 hover:text-white"
                                    >
                                        <Icons.X />
                                    </button>
                                </div>
                                
                                {/* Search filter */}
                                <div className="p-4 border-b border-proxmox-border">
                                    <input
                                        type="text"
                                        placeholder={t('searchTemplates') || 'Search templates...'}
                                        value={templateFilter}
                                        onChange={(e) => setTemplateFilter(e.target.value)}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500"
                                    />
                                </div>
                                
                                {/* Template list */}
                                <div className="flex-1 overflow-y-auto p-4">
                                    {templatesLoading ? (
                                        <div className="flex items-center justify-center py-12">
                                            <Icons.RotateCw className="animate-spin mr-2" />
                                            Loading templates...
                                        </div>
                                    ) : availableTemplates.length === 0 ? (
                                        <div className="text-center py-12 text-gray-500">
                                            <Icons.Package className="mx-auto mb-2 opacity-50" />
                                            <p>{t('noTemplatesAvailable') || 'No templates available'}</p>
                                        </div>
                                    ) : (
                                        <div className="space-y-2">
                                            {/* Group by section */}
                                            {Object.entries(
                                                availableTemplates
                                                    .filter(t => !templateFilter || 
                                                        t.package?.toLowerCase().includes(templateFilter.toLowerCase()) ||
                                                        t.headline?.toLowerCase().includes(templateFilter.toLowerCase()) ||
                                                        t.os?.toLowerCase().includes(templateFilter.toLowerCase())
                                                    )
                                                    .reduce((acc, t) => {
                                                        const section = t.section || 'Other';
                                                        if (!acc[section]) acc[section] = [];
                                                        acc[section].push(t);
                                                        return acc;
                                                    }, {})
                                            ).map(([section, templates]) => (
                                                <div key={section} className="mb-4">
                                                    <h4 className="text-sm font-semibold text-gray-400 uppercase mb-2 sticky top-0 bg-proxmox-card py-1">
                                                        {section} ({templates.length})
                                                    </h4>
                                                    <div className="space-y-1">
                                                        {templates.map((tmpl, idx) => (
                                                            <div 
                                                                key={idx}
                                                                className="flex items-center justify-between p-3 bg-proxmox-dark rounded-lg hover:bg-proxmox-hover group"
                                                            >
                                                                <div className="flex-1 min-w-0">
                                                                    <div className="flex items-center gap-2">
                                                                        <span className="font-medium text-white truncate">
                                                                            {tmpl.package || tmpl.template}
                                                                        </span>
                                                                        {tmpl.version && (
                                                                            <span className="text-xs bg-blue-500/20 text-blue-400 px-1.5 py-0.5 rounded">
                                                                                {tmpl.version}
                                                                            </span>
                                                                        )}
                                                                    </div>
                                                                    {tmpl.headline && (
                                                                        <p className="text-sm text-gray-400 truncate">{tmpl.headline}</p>
                                                                    )}
                                                                    <div className="flex items-center gap-2 mt-1 text-xs text-gray-500">
                                                                        {tmpl.os && <span>OS: {tmpl.os}</span>}
                                                                        {tmpl.infopage && (
                                                                            <a 
                                                                                href={tmpl.infopage} 
                                                                                target="_blank" 
                                                                                rel="noopener noreferrer"
                                                                                className="text-blue-400 hover:underline"
                                                                            >
                                                                                Info
                                                                            </a>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                                <button
                                                                    onClick={() => downloadTemplate(tmpl, selectedStorage.name)}
                                                                    disabled={downloadingTemplate === tmpl.template}
                                                                    className="flex items-center gap-1 px-3 py-1.5 bg-green-600 hover:bg-green-700 disabled:opacity-50 rounded-lg text-sm ml-2 whitespace-nowrap"
                                                                >
                                                                    {downloadingTemplate === tmpl.template ? (
                                                                        <><Icons.RotateCw className="animate-spin w-4 h-4" /> ...</>
                                                                    ) : (
                                                                        <><Icons.Download className="w-4 h-4" /> Download</>
                                                                    )}
                                                                </button>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                                
                                {/* Footer */}
                                <div className="p-4 border-t border-proxmox-border bg-proxmox-dark flex justify-between items-center text-sm text-gray-400">
                                    <span>
                                        {availableTemplates.length} {t('templatesAvailable') || 'templates available'}
                                    </span>
                                    <span>
                                        {t('downloadTo') || 'Download to'}: <strong className="text-white">{selectedStorage?.name}</strong>
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Storage Rescan Modal - NS Feb 2026 */}
                    {showRescanModal && selectedStorage && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-md">
                                <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                    <h3 className="text-lg font-semibold flex items-center gap-2">
                                        <Icons.RefreshCw className="text-purple-400" />
                                        {t('rescanStorage') || 'Rescan Storage'}
                                    </h3>
                                    <button
                                        onClick={() => setShowRescanModal(false)}
                                        className="p-1.5 hover:bg-proxmox-hover rounded-lg text-gray-400 hover:text-white"
                                        disabled={rescanLoading}
                                    >
                                        <Icons.X />
                                    </button>
                                </div>
                                <div className="p-4 space-y-4">
                                    <p className="text-gray-400 text-sm">
                                        {t('rescanStorageDesc') || `Rescan "${selectedStorage.name}" to detect changes.`}
                                    </p>
                                    
                                    {/* Quick Rescan Option */}
                                    <button
                                        onClick={async () => {
                                            setRescanLoading(true);
                                            try {
                                                addToast(t('rescanningStorage') || `Rescanning ${selectedStorage.name}...`, 'info');
                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/storage/${selectedStorage.name}/rescan`, {
                                                    method: 'POST',
                                                    headers: { 'Content-Type': 'application/json' },
                                                    body: JSON.stringify({ deep_scan: false })
                                                });
                                                const data = await res.json();
                                                if (res.ok && data.success) {
                                                    addToast(t('storageRescanSuccess') || `Rescan completed on ${data.nodes_successful}/${data.nodes_scanned} nodes`, 'success');
                                                    fetchDatastores();
                                                    loadStorageContent(selectedStorage.name, selectedStorage.node);
                                                } else {
                                                    addToast(data.error || 'Rescan failed', 'error');
                                                }
                                            } catch (e) {
                                                console.error('Rescan error:', e);
                                                addToast(t('storageRescanError') || 'Failed to rescan storage', 'error');
                                            } finally {
                                                setRescanLoading(false);
                                                setShowRescanModal(false);
                                            }
                                        }}
                                        disabled={rescanLoading}
                                        className="w-full p-4 bg-proxmox-dark hover:bg-proxmox-hover border border-proxmox-border rounded-xl text-left transition-colors disabled:opacity-50"
                                    >
                                        <div className="flex items-start gap-3">
                                            <div className="p-2 bg-blue-500/20 rounded-lg">
                                                <Icons.RefreshCw className="w-5 h-5 text-blue-400" />
                                            </div>
                                            <div>
                                                <h4 className="font-medium text-white">{t('quickRescan') || 'Quick Rescan'}</h4>
                                                <p className="text-sm text-gray-400 mt-1">
                                                    {t('quickRescanDesc') || 'Refresh storage status via API. Use for general status updates.'}
                                                </p>
                                            </div>
                                        </div>
                                    </button>
                                    
                                    {/* Deep Scan Option */}
                                    <button
                                        onClick={async () => {
                                            setRescanLoading(true);
                                            try {
                                                addToast(t('deepRescanningStorage') || `Deep rescanning ${selectedStorage.name}...`, 'info');
                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/storage/${selectedStorage.name}/rescan`, {
                                                    method: 'POST',
                                                    headers: { 'Content-Type': 'application/json' },
                                                    body: JSON.stringify({ deep_scan: true, pvresize: true })
                                                });
                                                const data = await res.json();
                                                if (res.ok && data.success) {
                                                    addToast(`Deep scan completed on ${data.nodes_successful}/${data.nodes_scanned} nodes`, 'success');
                                                    fetchDatastores();
                                                    loadStorageContent(selectedStorage.name, selectedStorage.node);
                                                } else {
                                                    addToast(data.error || 'Deep scan failed', 'error');
                                                }
                                            } catch (e) {
                                                console.error('Deep scan error:', e);
                                                addToast(t('storageRescanError') || 'Failed to rescan storage', 'error');
                                            } finally {
                                                setRescanLoading(false);
                                                setShowRescanModal(false);
                                            }
                                        }}
                                        disabled={rescanLoading}
                                        className="w-full p-4 bg-proxmox-dark hover:bg-proxmox-hover border border-purple-500/50 rounded-xl text-left transition-colors disabled:opacity-50"
                                    >
                                        <div className="flex items-start gap-3">
                                            <div className="p-2 bg-purple-500/20 rounded-lg">
                                                <Icons.Zap className="w-5 h-5 text-purple-400" />
                                            </div>
                                            <div>
                                                <h4 className="font-medium text-white flex items-center gap-2">
                                                    {t('deepRescan') || 'Deep Scan'}
                                                    <span className="text-xs px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded">{t('recommended') || 'Recommended'}</span>
                                                </h4>
                                                <p className="text-sm text-gray-400 mt-1">
                                                    {t('deepRescanDesc') || 'SSH-based SCSI rescan + multipath reconfigure + automatic pvresize. Use after LUN expansion or adding new LUNs.'}
                                                </p>
                                                <p className="text-xs text-yellow-500/80 mt-2 flex items-center gap-1">
                                                    <Icons.AlertTriangle className="w-3 h-3" />
                                                    {t('deepRescanNote') || 'Requires SSH access to nodes'}
                                                </p>
                                            </div>
                                        </div>
                                    </button>
                                    
                                    {rescanLoading && (
                                        <div className="flex items-center justify-center gap-2 py-2 text-gray-400">
                                            <Icons.Loader className="w-4 h-4 animate-spin" />
                                            {t('scanning') || 'Scanning...'}
                                        </div>
                                    )}
                                </div>
                                <div className="p-4 border-t border-proxmox-border bg-proxmox-dark/50">
                                    <button
                                        onClick={() => setShowRescanModal(false)}
                                        disabled={rescanLoading}
                                        className="w-full px-4 py-2 bg-proxmox-border hover:bg-proxmox-hover rounded-lg text-sm transition-colors disabled:opacity-50"
                                    >
                                        {t('cancel') || 'Cancel'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Upload Modal */}
                    {uploadModalOpen && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 w-full max-w-md">
                                <h3 className="text-lg font-semibold mb-4">{t('uploadIso') || 'Upload ISO'}</h3>
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-2">{t('selectFile') || 'Select File'}</label>
                                        <input
                                            type="file"
                                            accept=".iso"
                                            onChange={(e) => setUploadFile(e.target.files[0])}
                                            disabled={uploading}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white disabled:opacity-50"
                                        />
                                    </div>
                                    {uploadFile && (
                                        <div className="text-sm text-gray-400">
                                            📄 {uploadFile.name} ({formatSize(uploadFile.size)})
                                        </div>
                                    )}
                                    
                                    {/* Upload Progress */}
                                    {uploading && (
                                        <div className="space-y-2">
                                            <div className="flex justify-between text-sm">
                                                <span className="text-gray-400">
                                                    {uploadProgress < 100 ? 'Uploading...' : 'Processing...'}
                                                </span>
                                                <span className="text-proxmox-orange font-mono">
                                                    {uploadProgress}%
                                                </span>
                                            </div>
                                            <div className="w-full bg-proxmox-dark rounded-full h-3 overflow-hidden">
                                                <div 
                                                    className="h-full bg-gradient-to-r from-proxmox-orange to-orange-400 transition-all duration-300 ease-out"
                                                    style={{ width: `${uploadProgress}%` }}
                                                />
                                            </div>
                                            <div className="flex justify-between text-xs text-gray-500">
                                                <span>{formatSize(uploadFile.size * uploadProgress / 100)} / {formatSize(uploadFile.size)}</span>
                                                <span>{formatSpeed(uploadSpeed)}</span>
                                            </div>
                                        </div>
                                    )}
                                    
                                    <div className="flex gap-2 justify-end">
                                        <button
                                            onClick={() => { setUploadModalOpen(false); setUploadFile(null); setUploadProgress(0); }}
                                            disabled={uploading}
                                            className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg disabled:opacity-50"
                                        >
                                            {t('cancel') || 'Cancel'}
                                        </button>
                                        <button
                                            onClick={handleUpload}
                                            disabled={!uploadFile || uploading}
                                            className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg disabled:opacity-50 flex items-center gap-2"
                                        >
                                            {uploading ? (
                                                <>
                                                    <Icons.RotateCw className="animate-spin w-4 h-4" />
                                                    <span>{uploadProgress}%</span>
                                                </>
                                            ) : (
                                                <>
                                                    <Icons.Upload className="w-4 h-4" />
                                                    <span>{t('upload') || 'Upload'}</span>
                                                </>
                                            )}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Download from URL Modal - NS Jan 2026 */}
                    {downloadUrlModalOpen && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 w-full max-w-lg">
                                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                                    <Icons.Link className="w-5 h-5" />
                                    {t('downloadFromUrl') || 'Download from URL'}
                                </h3>
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-2">{t('isoUrl') || 'ISO URL'}</label>
                                        <input
                                            type="url"
                                            value={downloadUrl}
                                            onChange={(e) => setDownloadUrl(e.target.value)}
                                            placeholder="https://releases.ubuntu.com/22.04/ubuntu-22.04-live-server-amd64.iso"
                                            disabled={urlDownloading}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white disabled:opacity-50 text-sm"
                                        />
                                        <p className="text-xs text-gray-500 mt-1">
                                            {t('isoUrlHint') || 'Direct link to ISO file (http/https)'}
                                        </p>
                                    </div>
                                    
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-2">{t('filename') || 'Filename'} ({t('optional') || 'optional'})</label>
                                        <input
                                            type="text"
                                            value={downloadFilename}
                                            onChange={(e) => setDownloadFilename(e.target.value)}
                                            placeholder={t('autoDetect') || 'Auto-detect from URL'}
                                            disabled={urlDownloading}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white disabled:opacity-50 text-sm"
                                        />
                                    </div>
                                    
                                    <div className="bg-proxmox-dark/50 rounded-lg p-3 text-sm">
                                        <p className="text-gray-400">
                                            <strong>{t('storage') || 'Storage'}:</strong> {selectedStorage?.name}
                                            {selectedStorage?.node && <span className="text-gray-500"> ({selectedStorage.node})</span>}
                                        </p>
                                    </div>
                                    
                                    {/* Download Progress */}
                                    {urlDownloading && urlDownloadProgress && (
                                        <div className="space-y-2">
                                            <div className="flex justify-between text-sm">
                                                <span className="text-gray-400">
                                                    {urlDownloadProgress.message || 'Downloading...'}
                                                </span>
                                                {urlDownloadProgress.percent !== undefined && (
                                                    <span className="text-green-400 font-mono">
                                                        {urlDownloadProgress.percent}%
                                                    </span>
                                                )}
                                            </div>
                                            <div className="w-full bg-proxmox-dark rounded-full h-3 overflow-hidden">
                                                <div 
                                                    className="h-full bg-gradient-to-r from-green-500 to-green-400 transition-all duration-300 ease-out"
                                                    style={{ width: `${urlDownloadProgress.percent || 0}%` }}
                                                />
                                            </div>
                                            {urlDownloadProgress.downloaded && urlDownloadProgress.total && (
                                                <div className="flex justify-between text-xs text-gray-500">
                                                    <span>{formatSize(urlDownloadProgress.downloaded)} / {formatSize(urlDownloadProgress.total)}</span>
                                                    {urlDownloadProgress.speed && <span>{formatSpeed(urlDownloadProgress.speed)}</span>}
                                                </div>
                                            )}
                                        </div>
                                    )}
                                    
                                    <div className="flex gap-2 justify-end">
                                        <button
                                            onClick={() => { setDownloadUrlModalOpen(false); setDownloadUrl(''); setDownloadFilename(''); setUrlDownloadProgress(null); }}
                                            disabled={urlDownloading}
                                            className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg disabled:opacity-50"
                                        >
                                            {t('cancel') || 'Cancel'}
                                        </button>
                                        <button
                                            onClick={handleDownloadFromUrl}
                                            disabled={!downloadUrl || urlDownloading}
                                            className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg disabled:opacity-50 flex items-center gap-2"
                                        >
                                            {urlDownloading ? (
                                                <>
                                                    <Icons.RotateCw className="animate-spin w-4 h-4" />
                                                    <span>{t('downloading') || 'Downloading...'}</span>
                                                </>
                                            ) : (
                                                <>
                                                    <Icons.Download className="w-4 h-4" />
                                                    <span>{t('download') || 'Download'}</span>
                                                </>
                                            )}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* Delete Confirm Modal */}
                    {deleteConfirm && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 w-full max-w-md">
                                <h3 className="text-lg font-semibold mb-4 text-red-400">{t('confirmDelete') || 'Confirm Delete'}</h3>
                                <p className="text-gray-300 mb-4">
                                    {t('deleteConfirmText') || 'Are you sure you want to delete'}:<br/>
                                    <span className="font-mono text-sm">{deleteConfirm.volid?.split('/').pop()}</span>
                                </p>
                                <div className="flex gap-2 justify-end">
                                    <button
                                        onClick={() => setDeleteConfirm(null)}
                                        className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg"
                                    >
                                        {t('cancel') || 'Cancel'}
                                    </button>
                                    <button
                                        onClick={() => handleDelete(deleteConfirm)}
                                        className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg"
                                    >
                                        {t('delete') || 'Delete'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {/* MK: ESXi Connect Modal - Dec 2025 */}
                    {showAddEsxi && (
                        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50" onClick={() => setShowAddEsxi(false)}>
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 w-full max-w-md" onClick={e => e.stopPropagation()}>
                                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                                    <span className="text-xl">🖥️</span>
                                    {t('connectEsxi') || 'Connect ESXi Host'}
                                </h3>
                                
                                {/* Experimental warning */}
                                <div className="p-2 bg-yellow-500/10 border border-yellow-500/30 rounded-lg mb-4 flex items-center gap-2">
                                    <span>🧪</span>
                                    <span className="text-xs text-yellow-400">{t('esxiExperimental') || 'ESXi integration is experimental'}</span>
                                </div>
                                
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-2">{t('esxiHostname') || 'ESXi Hostname/IP'}</label>
                                        <input
                                            type="text"
                                            value={esxiForm.host}
                                            onChange={e => setEsxiForm({...esxiForm, host: e.target.value})}
                                            placeholder="192.168.1.100 oder esxi.local"
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-2">{t('esxiUsername') || 'Username'}</label>
                                        <input
                                            type="text"
                                            value={esxiForm.username}
                                            onChange={e => setEsxiForm({...esxiForm, username: e.target.value})}
                                            placeholder="root"
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-2">{t('esxiPassword') || 'Password'}</label>
                                        <input
                                            type="password"
                                            value={esxiForm.password}
                                            onChange={e => setEsxiForm({...esxiForm, password: e.target.value})}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                        />
                                    </div>
                                    
                                    <div className="flex gap-2 justify-end pt-2">
                                        <button
                                            onClick={() => setShowAddEsxi(false)}
                                            className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg"
                                        >
                                            {t('cancel') || 'Cancel'}
                                        </button>
                                        <button
                                            onClick={connectEsxiHost}
                                            disabled={esxiLoading || !esxiForm.host || !esxiForm.password}
                                            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 rounded-lg disabled:opacity-50 flex items-center gap-2"
                                        >
                                            {esxiLoading && <Icons.RotateCw className="animate-spin w-4 h-4" />}
                                            {t('connect') || 'Connect'}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            );
        }

