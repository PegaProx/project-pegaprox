        // ═══════════════════════════════════════════════
        // PegaProx - Create Modals
        // CreateVM, AddCluster, UserProfile
        // ═══════════════════════════════════════════════
        // Create VM/CT Modal Component
        // LW: This handles both QEMU VMs and LXC containers
        // The wizard steps are a bit complex but users seem to like it
        // ChatGPT helped with the step indicator UI - looks pretty clean
        // TODO: add template support for quick vm creation
        function CreateVmModal({ vmType, clusterId, nodes: initialNodes, onCreate, onClose }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [activeStep, setActiveStep] = useState(0);
            const [loading, setLoading] = useState(false);
            const [storageList, setStorageList] = useState([]);
            const [bridgeList, setBridgeList] = useState([]);
            const [isoList, setIsoList] = useState([]);
            const [templateList, setTemplateList] = useState([]);
            const [nextVmid, setNextVmid] = useState('');
            const [nodes, setNodes] = useState(initialNodes || []);
            // const [advancedMode, setAdvancedMode] = useState(false);  // someday
            
            const isQemu = vmType === 'qemu';
            
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
            
            // Fetch nodes if not provided
            useEffect(() => {
                const fetchNodes = async () => {
                    if(nodes.length === 0) {
                        try {
                            const response = await authFetch(`${API_URL}/clusters/${clusterId}/nodes`);
                            if(response && response.ok) {
                                const data = await response.json();
                                const nodeNames = data.map(n => n.node || n.name).filter(Boolean);
                                setNodes(nodeNames);
                                if(nodeNames.length > 0) {
                                    setConfig(prev => ({...prev, node: nodeNames[0]}));
                                }
                            }
                        } catch (e) {
                            console.error('fetching nodes:', e);
                        }
                    }
                };
                fetchNodes();
            }, [clusterId]);
            
            const [config, setConfig] = useState({
                // General
                node: nodes[0] || '',
                vmid: '',
                name: '',
                
                // OS (QEMU)
                ostype: 'l26',
                iso: '',
                virtio_iso: '', // VirtIO drivers ISO for Windows
                
                // Template (LXC)
                template: '',
                password: '',
                
                // Hardware
                cores: 2,
                sockets: 1,
                memory: 2048,
                memoryUnit: 'GB',  // LW: easier to work with GB by default
                
                // MK: Advanced CPU (QEMU)
                cpu_affinity: '',      // CPU affinity string e.g. "0-3" or "0,2,4"
                numa: false,           // Enable NUMA
                
                // MK: Advanced Memory (QEMU)
                min_memory: '',        // Minimum memory for ballooning (MB)
                min_memoryUnit: 'MB',  // MK: Unit for minimum memory
                ballooning: true,      // Ballooning device enabled
                shares: 1000,          // Memory shares (0-50000)
                
                // Disk
                storage: 'local-lvm',
                disk_size: isQemu ? '32' : '8',
                disk_type: 'scsi',  // scsi, virtio, ide, sata
                disk_format: '',    // raw, qcow2, vmdk (empty = storage default)
                disk_cache: '',     // none, directsync, writethrough, writeback, unsafe
                disk_discard: true,
                disk_iothread: true,
                disk_ssd: false,
                additional_disks: [], // MK: Array of additional disks {storage, size, type, format}
                
                // Network
                net_bridge: 'vmbr0',
                net_model: 'virtio',
                net_firewall: true,
                net_tag: '',
                net_ip: 'dhcp',
                net_gw: '',
                // MK: Advanced Network
                net_macaddr: '',       // Custom MAC address
                net_disconnect: false, // Disconnect network
                net_mtu: '',           // MTU (1-65520)
                net_rate: '',          // Rate limit in MB/s
                
                // Advanced (QEMU)
                cpu: 'host',
                bios: 'seabios',
                machine: 'i440fx',
                scsihw: 'virtio-scsi-pci',
                vga: 'std',
                agent: true,
                efi_storage: '',     // Storage for EFI disk
                efi_pre_enroll: true, // Pre-enroll Microsoft keys
                tpm_storage: '',     // Storage for TPM state
                tpm_version: 'v2.0', // TPM version
                ha_enabled: false,   // MK: Enable Proxmox native HA
                ha_group: '',        // MK: HA group name
                
                // Advanced (LXC)
                unprivileged: true,
                nesting: false,
                swap: 512,
                swapUnit: 'MB',  // NS: unit selector for swap
                ssh_public_keys: '',
                
                // Network (extended for LXC)
                net_ip_type: 'dhcp',      // dhcp, static, manual
                net_ip6_type: 'dhcp',     // dhcp, static, slaac, manual
                net_ip6: '',
                net_gw6: '',
                net_disconnected: false,
                
                // DNS
                dns_domain: '',
                dns_servers: '',
                
                // Options
                onboot: false,
                start: false,
            });

            useEffect(() => {
                // Set default node if available
                if(nodes.length > 0 && !config.node) {
                    setConfig(prev => ({...prev, node: nodes[0]}));
                }
            }, [nodes]);
            
            useEffect(() => {
                if(config.node) {
                    fetchStorageList();
                    fetchBridgeList();
                    if(isQemu) fetchIsoList();
                    else fetchTemplateList();
                    fetchNextVmid();
                }
            }, [config.node]);

            const fetchStorageList = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${config.node}/storage`);
                    if(response && response.ok) {
                        const data = await response.json();
                        setStorageList(data);
                        // Set default storage if current is not in list
                        if(data.length > 0 && !data.find(s => s.storage === config.storage)) {
                            const defaultStorage = data.find(s => s.storage === 'local-lvm') || data[0];
                            setConfig(prev => ({...prev, storage: defaultStorage.storage}));
                        }
                    }
                } catch (e) { console.error(e); }
            };

            const fetchBridgeList = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${config.node}/networks`);
                    if(response && response.ok) {
                        const data = await response.json();
                        setBridgeList(data);
                        // Set default bridge (prefer vmbr0, then any local bridge, then SDN vnet, then first available)
                        if(data.length > 0 && !data.find(b => b.iface === config.net_bridge)) {
                            const defaultBridge = data.find(b => b.iface === 'vmbr0') || 
                                                  data.find(b => b.type === 'bridge' || b.type === 'OVSBridge') || 
                                                  data.find(b => b.source === 'sdn') ||
                                                  data[0];
                            if(defaultBridge) setConfig(prev => ({...prev, net_bridge: defaultBridge.iface}));
                        }
                    }
                } catch (e) { console.error(e); }
            };

            const fetchIsoList = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${config.node}/isos`);
                    if(response && response.ok) {
                        const data = await response.json();
                        setIsoList(data);
                        console.log('Loaded ISOs:', data);
                    }
                } catch (e) { console.error('loading ISOs:', e); }
            };

            const fetchTemplateList = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${config.node}/templates`);
                    if(response && response.ok) setTemplateList(await response.json());
                } catch (e) { console.error(e); }
            };

            const fetchNextVmid = async () => {
                try {
                    const response = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${config.node}/nextid`);
                    if(response && response.ok) {
                        const data = await response.json();
                        setNextVmid(data.vmid);
                        if(!config.vmid) setConfig(prev => ({...prev, vmid: data.vmid}));
                    }
                } catch (e) { console.error(e); }
            };

            const handleCreate = async () => {
                setLoading(true);
                await onCreate(vmType, config.node, config);
                setLoading(false);
            };

            const steps = isQemu 
                ? [t('general'), t('os'), t('hardware'), t('disk'), t('network'), t('advanced')]
                : [t('general'), t('template'), t('resources'), t('disk'), t('network'), t('options')];

            const osTypes = [
                { value: 'l26', label: 'Linux 2.6+ Kernel' },
                { value: 'l24', label: 'Linux 2.4 Kernel' },
                { value: 'win11', label: 'Windows 11/2022' },
                { value: 'win10', label: 'Windows 10/2016/2019' },
                { value: 'win8', label: 'Windows 8/2012' },
                { value: 'win7', label: 'Windows 7/2008' },
                { value: 'wxp', label: 'Windows XP/2003' },
                { value: 'other', label: 'Other' },
            ];

            const cpuTypes = [
                'host', 'kvm64', 'kvm32', 'qemu64', 'qemu32', 'max',
                'Broadwell', 'Broadwell-IBRS', 'Broadwell-noTSX', 'Broadwell-noTSX-IBRS',
                'Cascadelake-Server', 'Cascadelake-Server-noTSX', 'Conroe', 'EPYC', 'EPYC-IBPB',
                'EPYC-Milan', 'EPYC-Rome', 'Haswell', 'Haswell-IBRS', 'Haswell-noTSX',
                'Haswell-noTSX-IBRS', 'Icelake-Client', 'Icelake-Client-noTSX', 'Icelake-Server',
                'Icelake-Server-noTSX', 'IvyBridge', 'IvyBridge-IBRS', 'KnightsMill', 'Nehalem',
                'Nehalem-IBRS', 'Opteron_G1', 'Opteron_G2', 'Opteron_G3', 'Opteron_G4', 'Opteron_G5',
                'Penryn', 'SandyBridge', 'SandyBridge-IBRS', 'Skylake-Client', 'Skylake-Client-IBRS',
                'Skylake-Client-noTSX-IBRS', 'Skylake-Server', 'Skylake-Server-IBRS',
                'Skylake-Server-noTSX-IBRS', 'Westmere', 'Westmere-IBRS', 'athlon', 'core2duo',
                'coreduo', 'n270', 'pentium', 'pentium2', 'pentium3', 'phenom', 'x86-64-v2',
                'x86-64-v2-AES', 'x86-64-v3', 'x86-64-v4'
            ];

            const vgaTypes = [
                { value: 'std', label: 'Standard VGA' },
                { value: 'vmware', label: 'VMware compatible' },
                { value: 'qxl', label: 'SPICE (QXL)' },
                { value: 'qxl2', label: 'SPICE (QXL) 2 heads' },
                { value: 'qxl3', label: 'SPICE (QXL) 3 heads' },
                { value: 'qxl4', label: 'SPICE (QXL) 4 heads' },
                { value: 'virtio', label: 'VirtIO-GPU' },
                { value: 'virtio-gl', label: 'VirtIO-GPU (virgl)' },
                { value: 'cirrus', label: 'Cirrus Logic' },
                { value: 'none', label: 'None (headless)' },
            ];

            const scsiControllers = [
                { value: 'virtio-scsi-pci', label: 'VirtIO SCSI' },
                { value: 'virtio-scsi-single', label: 'VirtIO SCSI Single' },
                { value: 'lsi', label: 'LSI 53C895A' },
                { value: 'lsi53c810', label: 'LSI 53C810' },
                { value: 'megasas', label: 'MegaRAID SAS' },
                { value: 'pvscsi', label: 'VMware PVSCSI' },
            ];

            const renderStepContent = () => {
                // Filter storages by content type
                const diskStorages = storageList.filter(s => {
                    const content = s.content || '';
                    return content.includes('images') || content.includes('rootdir') || s.type === 'lvmthin' || s.type === 'lvm' || s.type === 'zfspool' || s.type === 'rbd' || s.type === 'dir';
                });
                const isoStorages = storageList.filter(s => (s.content || '').includes('iso'));
                const templateStorages = storageList.filter(s => (s.content || '').includes('vztmpl'));
                
                if(isQemu) {
                    switch(activeStep) {
                        case 0: // General
                            return (
                                <div className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('node')}</label>
                                            <select value={config.node} onChange={e => setConfig({...config, node: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                {nodes.map(n => <option key={n} value={n}>{n}</option>)}
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">VM ID</label>
                                            <input type="number" value={config.vmid} onChange={e => setConfig({...config, vmid: e.target.value})}
                                                placeholder={nextVmid ? `${t('next')}: ${nextVmid}` : ''}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                        </div>
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('name')}</label>
                                        <input type="text" value={config.name} onChange={e => setConfig({...config, name: e.target.value})}
                                            placeholder="my-virtual-machine"
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                    </div>
                                </div>
                            );
                        case 1: // OS
                            return (
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('guestOs')}</label>
                                        <select value={config.ostype} onChange={e => setConfig({...config, ostype: e.target.value})}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                            {osTypes.map(os => <option key={os.value} value={os.value}>{os.label}</option>)}
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('isoImage')}</label>
                                        <select value={config.iso} onChange={e => setConfig({...config, iso: e.target.value})}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                            <option value="">{t('noIso')}</option>
                                            {isoList.length === 0 && <option disabled>{t('noIsoAvailable')}</option>}
                                            {isoList.map(iso => <option key={iso.volid} value={iso.volid}>{iso.volid.split('/').pop()}</option>)}
                                        </select>
                                        {isoStorages.length === 0 && (
                                            <p className="text-xs text-yellow-500 mt-1">⚠️ {t('noIsoStorage')}</p>
                                        )}
                                    </div>
                                    {config.ostype.startsWith('win') && (
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('virtioDrivers')}</label>
                                            <select value={config.virtio_iso} onChange={e => setConfig({...config, virtio_iso: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                <option value="">{t('noVirtioDrivers')}</option>
                                                {isoList.filter(iso => iso.volid.toLowerCase().includes('virtio')).map(iso => (
                                                    <option key={iso.volid} value={iso.volid}>{iso.volid.split('/').pop()}</option>
                                                ))}
                                                <optgroup label={t('allIsos')}>
                                                    {isoList.map(iso => <option key={iso.volid} value={iso.volid}>{iso.volid.split('/').pop()}</option>)}
                                                </optgroup>
                                            </select>
                                            <p className="text-xs text-gray-500 mt-1">{t('virtioDriversHint')}</p>
                                        </div>
                                    )}
                                </div>
                            );
                        case 2: // Hardware
                            return (
                                <div className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('sockets')}</label>
                                            <input type="number" min="1" max="4" value={config.sockets} onChange={e => setConfig({...config, sockets: parseInt(e.target.value)})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('cores')}</label>
                                            <input type="number" min="1" max="128" value={config.cores} onChange={e => setConfig({...config, cores: parseInt(e.target.value)})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                        </div>
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('memory')}</label>
                                        <div className="flex gap-2">
                                            <input type="number" min={config.memoryUnit === 'GB' ? 0.5 : 128} step={config.memoryUnit === 'GB' ? 0.5 : 128} 
                                                value={config.memoryUnit === 'GB' ? (config.memory / 1024) : config.memory} 
                                                onChange={e => {
                                                    const val = parseFloat(e.target.value) || 0;
                                                    setConfig({...config, memory: config.memoryUnit === 'GB' ? Math.round(val * 1024) : val});
                                                }}
                                                className="flex-1 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                            <select value={config.memoryUnit || 'MB'} onChange={e => setConfig({...config, memoryUnit: e.target.value})}
                                                className="w-20 px-2 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                <option value="MB">MB</option>
                                                <option value="GB">GB</option>
                                            </select>
                                        </div>
                                        <p className="text-xs text-gray-500 mt-1">
                                            {config.memoryUnit === 'GB' ? `${config.memory} MB` : `${(config.memory / 1024).toFixed(1)} GB`}
                                        </p>
                                    </div>
                                    
                                    {/* MK: Advanced CPU Section */}
                                    <details className="group">
                                        <summary className="flex items-center justify-between cursor-pointer p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg hover:bg-blue-500/20">
                                            <span className="text-sm font-medium text-blue-400">{t('advancedCpu') || 'Advanced CPU'}</span>
                                            <Icons.ChevronDown className="w-4 h-4 text-blue-400 group-open:rotate-180 transition-transform" />
                                        </summary>
                                        <div className="mt-3 space-y-3 p-3 bg-proxmox-dark/50 rounded-lg">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">{t('cpuAffinity') || 'CPU Affinity'}</label>
                                                <input type="text" value={config.cpu_affinity} onChange={e => setConfig({...config, cpu_affinity: e.target.value})}
                                                    placeholder="e.g. 0-3 or 0,2,4,6"
                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                                <p className="text-xs text-gray-500 mt-1">{t('cpuAffinityHint') || 'Pin vCPUs to specific host CPUs'}</p>
                                            </div>
                                            <label className="flex items-center gap-2 text-sm text-gray-300">
                                                <input type="checkbox" checked={config.numa} onChange={e => setConfig({...config, numa: e.target.checked})} className="rounded" />
                                                {t('enableNuma') || 'Enable NUMA'}
                                            </label>
                                        </div>
                                    </details>
                                    
                                    {/* MK: Advanced Memory Section */}
                                    <details className="group">
                                        <summary className="flex items-center justify-between cursor-pointer p-3 bg-purple-500/10 border border-purple-500/30 rounded-lg hover:bg-purple-500/20">
                                            <span className="text-sm font-medium text-purple-400">{t('advancedMemory') || 'Advanced Memory'}</span>
                                            <Icons.ChevronDown className="w-4 h-4 text-purple-400 group-open:rotate-180 transition-transform" />
                                        </summary>
                                        <div className="mt-3 space-y-3 p-3 bg-proxmox-dark/50 rounded-lg">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">{t('minimumMemory') || 'Minimum Memory'}</label>
                                                <div className="flex gap-2">
                                                    <input type="number" min="0" 
                                                        value={config.min_memoryUnit === 'GB' ? (config.min_memory ? config.min_memory / 1024 : '') : (config.min_memory || '')}
                                                        onChange={e => {
                                                            const val = parseFloat(e.target.value) || '';
                                                            if (val === '') {
                                                                setConfig({...config, min_memory: ''});
                                                            } else {
                                                                setConfig({...config, min_memory: config.min_memoryUnit === 'GB' ? Math.round(val * 1024) : val});
                                                            }
                                                        }}
                                                        placeholder={t('sameAsMemory') || 'Same as Memory'}
                                                        className="flex-1 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                                    <select value={config.min_memoryUnit || 'MB'} onChange={e => setConfig({...config, min_memoryUnit: e.target.value})}
                                                        className="w-20 px-2 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                        <option value="MB">MB</option>
                                                        <option value="GB">GB</option>
                                                    </select>
                                                </div>
                                                <p className="text-xs text-gray-500 mt-1">{t('minimumMemoryHint') || 'Lower limit for memory ballooning'}</p>
                                            </div>
                                            <div className="grid grid-cols-2 gap-4">
                                                <label className="flex items-center gap-2 text-sm text-gray-300">
                                                    <input type="checkbox" checked={config.ballooning} onChange={e => setConfig({...config, ballooning: e.target.checked})} className="rounded" />
                                                    {t('ballooningDevice') || 'Ballooning Device'}
                                                </label>
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">{t('memoryShares') || 'Memory Shares'}</label>
                                                <input type="number" min="0" max="50000" value={config.shares} onChange={e => setConfig({...config, shares: parseInt(e.target.value) || 0})}
                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                                <p className="text-xs text-gray-500 mt-1">{t('memorySharesHint') || 'Weight for memory auto-ballooning (0-50000, default: 1000)'}</p>
                                            </div>
                                        </div>
                                    </details>
                                </div>
                            );
                        case 3: // Disk
                            // MK: Helper to render storage bar
                            const renderStorageBar = (selectedStorage) => {
                                const storageInfo = diskStorages.find(s => s.storage === selectedStorage);
                                if (!storageInfo) return null;
                                const total = storageInfo.total || storageInfo.maxdisk || storageInfo.avail || 0;
                                const avail = storageInfo.avail || 0;
                                if (total <= 0) return null;
                                const usedPercent = total > 0 ? ((total - avail) / total) * 100 : 0;
                                const freeGB = (avail / 1024 / 1024 / 1024).toFixed(1);
                                return (
                                    <div className="mt-2">
                                        <div className="flex justify-between text-xs text-gray-500 mb-1">
                                            <span>{freeGB} GB {t('free')}</span>
                                            <span>{usedPercent.toFixed(0)}% {t('used')}</span>
                                        </div>
                                        <div className="h-1.5 bg-proxmox-dark rounded-full overflow-hidden">
                                            <div className={`h-full ${usedPercent > 90 ? 'bg-red-500' : usedPercent > 70 ? 'bg-yellow-500' : 'bg-green-500'}`}
                                                style={{ width: `${usedPercent}%` }} />
                                        </div>
                                    </div>
                                );
                            };
                            
                            return (
                                <div className="space-y-4">
                                    {/* MK: Primary Disk with ALL options */}
                                    <div className="p-4 bg-proxmox-dark/50 rounded-lg border border-proxmox-border">
                                        <h4 className="text-sm font-medium text-white mb-3">{t('primaryDisk') || 'Disk'} 0 ({config.disk_type}0)</h4>
                                        <div className="grid grid-cols-4 gap-3 mb-3">
                                            <div>
                                                <label className="block text-xs text-gray-400 mb-1">{t('busType')}</label>
                                                <select value={config.disk_type} onChange={e => setConfig({...config, disk_type: e.target.value})}
                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                    <option value="scsi">SCSI</option>
                                                    <option value="virtio">VirtIO Block</option>
                                                    <option value="ide">IDE</option>
                                                    <option value="sata">SATA</option>
                                                </select>
                                            </div>
                                            <div className="col-span-2">
                                                <label className="block text-xs text-gray-400 mb-1">{t('storage')}</label>
                                                <select value={config.storage} onChange={e => setConfig({...config, storage: e.target.value})}
                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                    {diskStorages.map(s => (
                                                        <option key={s.storage} value={s.storage}>
                                                            {s.storage} ({s.type})
                                                        </option>
                                                    ))}
                                                </select>
                                                {renderStorageBar(config.storage)}
                                            </div>
                                            <div>
                                                <label className="block text-xs text-gray-400 mb-1">{t('size')} (GB)</label>
                                                <input type="number" min="1" value={config.disk_size} onChange={e => setConfig({...config, disk_size: e.target.value})}
                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                            </div>
                                        </div>
                                        <div className="grid grid-cols-4 gap-3 mb-3">
                                            <div>
                                                <label className="block text-xs text-gray-400 mb-1">{t('format')}</label>
                                                <select value={config.disk_format} onChange={e => setConfig({...config, disk_format: e.target.value})}
                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                    <option value="">{t('storageDefault') || 'Default'}</option>
                                                    <option value="raw">Raw</option>
                                                    <option value="qcow2">QCOW2</option>
                                                    <option value="vmdk">VMDK</option>
                                                </select>
                                            </div>
                                            <div>
                                                <label className="block text-xs text-gray-400 mb-1">{t('cache')}</label>
                                                <select value={config.disk_cache} onChange={e => setConfig({...config, disk_cache: e.target.value})}
                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                    <option value="">{t('default') || 'Default'}</option>
                                                    <option value="directsync">Direct Sync</option>
                                                    <option value="writethrough">Write Through</option>
                                                    <option value="writeback">Write Back</option>
                                                    <option value="none">{t('none') || 'None'}</option>
                                                </select>
                                            </div>
                                            {config.disk_type === 'scsi' && (
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('scsiController')}</label>
                                                    <select value={config.scsihw} onChange={e => setConfig({...config, scsihw: e.target.value})}
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                        {scsiControllers.map(sc => <option key={sc.value} value={sc.value}>{sc.label}</option>)}
                                                    </select>
                                                </div>
                                            )}
                                        </div>
                                        <div className="flex flex-wrap gap-4">
                                            <label className="flex items-center gap-2 text-xs text-gray-300">
                                                <input type="checkbox" checked={config.disk_discard} onChange={e => setConfig({...config, disk_discard: e.target.checked})} className="rounded" />
                                                {t('discard')} (TRIM)
                                            </label>
                                            {config.disk_type === 'scsi' && (
                                                <label className="flex items-center gap-2 text-xs text-gray-300">
                                                    <input type="checkbox" checked={config.disk_iothread} onChange={e => setConfig({...config, disk_iothread: e.target.checked})} className="rounded" />
                                                    {t('ioThread')}
                                                </label>
                                            )}
                                            <label className="flex items-center gap-2 text-xs text-gray-300">
                                                <input type="checkbox" checked={config.disk_ssd} onChange={e => setConfig({...config, disk_ssd: e.target.checked})} className="rounded" />
                                                {t('ssdEmulation')}
                                            </label>
                                        </div>
                                    </div>
                                    
                                    {/* MK: Additional Disks - each with ALL options */}
                                    {config.additional_disks.map((disk, idx) => (
                                        <div key={idx} className="p-4 bg-proxmox-dark/50 rounded-lg border border-proxmox-border">
                                            <div className="flex items-center justify-between mb-3">
                                                <h4 className="text-sm font-medium text-white">{t('disk') || 'Disk'} {idx + 1} ({disk.type}{idx + 1})</h4>
                                                <button onClick={() => setConfig({...config, additional_disks: config.additional_disks.filter((_, i) => i !== idx)})}
                                                    className="p-1 text-red-400 hover:bg-red-500/20 rounded">
                                                    <Icons.Trash2 className="w-4 h-4" />
                                                </button>
                                            </div>
                                            <div className="grid grid-cols-4 gap-3 mb-3">
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('busType')}</label>
                                                    <select value={disk.type} onChange={e => {
                                                        const newDisks = [...config.additional_disks];
                                                        newDisks[idx] = {...disk, type: e.target.value};
                                                        setConfig({...config, additional_disks: newDisks});
                                                    }}
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                        <option value="scsi">SCSI</option>
                                                        <option value="virtio">VirtIO Block</option>
                                                        <option value="sata">SATA</option>
                                                    </select>
                                                </div>
                                                <div className="col-span-2">
                                                    <label className="block text-xs text-gray-400 mb-1">{t('storage')}</label>
                                                    <select value={disk.storage} onChange={e => {
                                                        const newDisks = [...config.additional_disks];
                                                        newDisks[idx] = {...disk, storage: e.target.value};
                                                        setConfig({...config, additional_disks: newDisks});
                                                    }}
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                        {diskStorages.map(s => <option key={s.storage} value={s.storage}>{s.storage} ({s.type})</option>)}
                                                    </select>
                                                    {renderStorageBar(disk.storage)}
                                                </div>
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('size')} (GB)</label>
                                                    <input type="number" min="1" value={disk.size} onChange={e => {
                                                        const newDisks = [...config.additional_disks];
                                                        newDisks[idx] = {...disk, size: e.target.value};
                                                        setConfig({...config, additional_disks: newDisks});
                                                    }}
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                </div>
                                            </div>
                                            <div className="grid grid-cols-4 gap-3 mb-3">
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('format')}</label>
                                                    <select value={disk.format || ''} onChange={e => {
                                                        const newDisks = [...config.additional_disks];
                                                        newDisks[idx] = {...disk, format: e.target.value};
                                                        setConfig({...config, additional_disks: newDisks});
                                                    }}
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                        <option value="">{t('storageDefault') || 'Default'}</option>
                                                        <option value="raw">Raw</option>
                                                        <option value="qcow2">QCOW2</option>
                                                        <option value="vmdk">VMDK</option>
                                                    </select>
                                                </div>
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('cache')}</label>
                                                    <select value={disk.cache || ''} onChange={e => {
                                                        const newDisks = [...config.additional_disks];
                                                        newDisks[idx] = {...disk, cache: e.target.value};
                                                        setConfig({...config, additional_disks: newDisks});
                                                    }}
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                        <option value="">{t('default') || 'Default'}</option>
                                                        <option value="directsync">Direct Sync</option>
                                                        <option value="writethrough">Write Through</option>
                                                        <option value="writeback">Write Back</option>
                                                        <option value="none">{t('none') || 'None'}</option>
                                                    </select>
                                                </div>
                                                {disk.type === 'scsi' && (
                                                    <div>
                                                        <label className="block text-xs text-gray-400 mb-1">{t('scsiController')}</label>
                                                        <select value={disk.scsihw || config.scsihw} onChange={e => {
                                                            const newDisks = [...config.additional_disks];
                                                            newDisks[idx] = {...disk, scsihw: e.target.value};
                                                            setConfig({...config, additional_disks: newDisks});
                                                        }}
                                                            className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                            <option value="virtio-scsi-pci">VirtIO SCSI</option>
                                                            <option value="virtio-scsi-single">VirtIO Single</option>
                                                            <option value="lsi">LSI 53C895A</option>
                                                            <option value="megasas">MegaRAID SAS</option>
                                                        </select>
                                                    </div>
                                                )}
                                            </div>
                                            <div className="flex flex-wrap gap-4">
                                                <label className="flex items-center gap-2 text-xs text-gray-300">
                                                    <input type="checkbox" checked={disk.discard !== false} onChange={e => {
                                                        const newDisks = [...config.additional_disks];
                                                        newDisks[idx] = {...disk, discard: e.target.checked};
                                                        setConfig({...config, additional_disks: newDisks});
                                                    }} className="rounded" />
                                                    {t('discard')} (TRIM)
                                                </label>
                                                {disk.type === 'scsi' && (
                                                    <label className="flex items-center gap-2 text-xs text-gray-300">
                                                        <input type="checkbox" checked={disk.iothread !== false} onChange={e => {
                                                            const newDisks = [...config.additional_disks];
                                                            newDisks[idx] = {...disk, iothread: e.target.checked};
                                                            setConfig({...config, additional_disks: newDisks});
                                                        }} className="rounded" />
                                                        {t('ioThread')}
                                                    </label>
                                                )}
                                                <label className="flex items-center gap-2 text-xs text-gray-300">
                                                    <input type="checkbox" checked={disk.ssd || false} onChange={e => {
                                                        const newDisks = [...config.additional_disks];
                                                        newDisks[idx] = {...disk, ssd: e.target.checked};
                                                        setConfig({...config, additional_disks: newDisks});
                                                    }} className="rounded" />
                                                    {t('ssdEmulation')}
                                                </label>
                                            </div>
                                        </div>
                                    ))}
                                    
                                    {/* MK: Add Disk Button */}
                                    <button onClick={() => setConfig({...config, additional_disks: [...config.additional_disks, {type: 'scsi', storage: config.storage, size: '32', format: '', cache: '', discard: true, iothread: true, ssd: false}]})}
                                        className="w-full px-4 py-2 border-2 border-dashed border-proxmox-border rounded-lg text-gray-400 hover:text-white hover:border-proxmox-orange transition-colors">
                                        + {t('addDisk') || 'Add Disk'}
                                    </button>
                                </div>
                            );
                        case 4: // Network
                            return (
                                <div className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('bridge')} / VNet</label>
                                            <select value={config.net_bridge} onChange={e => setConfig({...config, net_bridge: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
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
                                                {bridgeList.length === 0 && <option value="vmbr0">vmbr0</option>}
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('model')}</label>
                                            <select value={config.net_model} onChange={e => setConfig({...config, net_model: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                <option value="virtio">VirtIO (paravirtualized)</option>
                                                <option value="e1000">Intel E1000</option>
                                                <option value="rtl8139">Realtek RTL8139</option>
                                                <option value="vmxnet3">VMware vmxnet3</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('vlanTag')}</label>
                                            <input type="text" value={config.net_tag} onChange={e => setConfig({...config, net_tag: e.target.value})}
                                                placeholder={t('vlanExample')}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('macAddress') || 'MAC Address'}</label>
                                            <input type="text" value={config.net_macaddr} onChange={e => setConfig({...config, net_macaddr: e.target.value})}
                                                placeholder={t('autoGenerate') || 'Auto-generate (leave empty)'}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                        </div>
                                    </div>
                                    
                                    {/* MK: Advanced Network Options */}
                                    <details className="group">
                                        <summary className="flex items-center justify-between cursor-pointer p-3 bg-green-500/10 border border-green-500/30 rounded-lg hover:bg-green-500/20">
                                            <span className="text-sm font-medium text-green-400">{t('advancedNetwork') || 'Advanced Network'}</span>
                                            <Icons.ChevronDown className="w-4 h-4 text-green-400 group-open:rotate-180 transition-transform" />
                                        </summary>
                                        <div className="mt-3 space-y-3 p-3 bg-proxmox-dark/50 rounded-lg">
                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">MTU</label>
                                                    <input type="number" min="1" max="65520" value={config.net_mtu} onChange={e => setConfig({...config, net_mtu: e.target.value})}
                                                        placeholder={t('inheritBridge') || 'Inherit from bridge'}
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('rateLimit') || 'Rate Limit'} (MB/s)</label>
                                                    <input type="number" min="0" step="0.1" value={config.net_rate} onChange={e => setConfig({...config, net_rate: e.target.value})}
                                                        placeholder={t('unlimited') || 'Unlimited'}
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                                </div>
                                            </div>
                                            <label className="flex items-center gap-2 text-sm text-gray-300">
                                                <input type="checkbox" checked={config.net_disconnect} onChange={e => setConfig({...config, net_disconnect: e.target.checked})} className="rounded" />
                                                {t('disconnected') || 'Disconnected'} ({t('noLinkOnStart') || 'No network link on start'})
                                            </label>
                                        </div>
                                    </details>
                                    
                                    <label className="flex items-center gap-2 text-sm text-gray-300">
                                        <input type="checkbox" checked={config.net_firewall} onChange={e => setConfig({...config, net_firewall: e.target.checked})} className="rounded" />
                                        {t('enableFirewall')}
                                    </label>
                                </div>
                            );
                        case 5: // Advanced
                            return (
                                <div className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('cpuType')}</label>
                                            <select value={config.cpu} onChange={e => setConfig({...config, cpu: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                {cpuTypes.map(cpu => <option key={cpu} value={cpu}>{cpu}</option>)}
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">BIOS</label>
                                            <select value={config.bios} onChange={e => {
                                                const newBios = e.target.value;
                                                setConfig({
                                                    ...config, 
                                                    bios: newBios,
                                                    machine: newBios === 'ovmf' ? 'q35' : config.machine,
                                                    efi_storage: newBios === 'ovmf' ? config.storage : ''
                                                });
                                            }}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                <option value="seabios">SeaBIOS (Legacy BIOS)</option>
                                                <option value="ovmf">OVMF (UEFI)</option>
                                            </select>
                                        </div>
                                    </div>
                                    
                                    {/* EFI Settings */}
                                    {config.bios === 'ovmf' && (
                                        <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg space-y-3">
                                            <h4 className="text-sm font-medium text-blue-400">{t('efiSettings')}</h4>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('efiDiskStorage')}</label>
                                                    <select value={config.efi_storage || config.storage} onChange={e => setConfig({...config, efi_storage: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                        {diskStorages.map(s => <option key={s.storage} value={s.storage}>{s.storage}</option>)}
                                                    </select>
                                                </div>
                                                <div className="flex items-end">
                                                    <label className="flex items-center gap-2 text-sm text-gray-300">
                                                        <input type="checkbox" checked={config.efi_pre_enroll} onChange={e => setConfig({...config, efi_pre_enroll: e.target.checked})} className="rounded" />
                                                        {t('preEnrollKeys')}
                                                    </label>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    
                                    {/* TPM Settings */}
                                    <div className="p-4 bg-purple-500/10 border border-purple-500/30 rounded-lg space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h4 className="text-sm font-medium text-purple-400">{t('tpmSettings')}</h4>
                                            <label className="flex items-center gap-2 text-sm text-gray-300">
                                                <input type="checkbox" checked={!!config.tpm_storage} onChange={e => setConfig({...config, tpm_storage: e.target.checked ? config.storage : ''})} className="rounded" />
                                                {t('enableTpm')}
                                            </label>
                                        </div>
                                        {config.tpm_storage && (
                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('tpmStorage')}</label>
                                                    <select value={config.tpm_storage} onChange={e => setConfig({...config, tpm_storage: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                        {diskStorages.map(s => <option key={s.storage} value={s.storage}>{s.storage}</option>)}
                                                    </select>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('tpmVersion')}</label>
                                                    <select value={config.tpm_version} onChange={e => setConfig({...config, tpm_version: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                        <option value="v2.0">TPM 2.0 ({t('recommended')})</option>
                                                        <option value="v1.2">TPM 1.2</option>
                                                    </select>
                                                </div>
                                            </div>
                                        )}
                                        {config.ostype.startsWith('win11') && !config.tpm_storage && (
                                            <p className="text-xs text-yellow-400">⚠️ {t('win11NeedsTpm')}</p>
                                        )}
                                    </div>

                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('machineType')}</label>
                                            <select value={config.machine} onChange={e => setConfig({...config, machine: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                <optgroup label="i440fx (Standard)">
                                                    <option value="i440fx">i440fx (Latest)</option>
                                                    <option value="pc-i440fx-10.1">i440fx 10.1</option>
                                                    <option value="pc-i440fx-9.2+pve1">i440fx 9.2+pve1</option>
                                                    <option value="pc-i440fx-8.2">i440fx 8.2</option>
                                                    <option value="pc-i440fx-7.2">i440fx 7.2</option>
                                                </optgroup>
                                                <optgroup label="q35 (Modern, PCIe)">
                                                    <option value="q35">q35 (Latest)</option>
                                                    <option value="pc-q35-10.1">q35 10.1</option>
                                                    <option value="pc-q35-9.2+pve1">q35 9.2+pve1</option>
                                                    <option value="pc-q35-8.2">q35 8.2</option>
                                                    <option value="pc-q35-7.2">q35 7.2</option>
                                                </optgroup>
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">VGA</label>
                                            <select value={config.vga} onChange={e => setConfig({...config, vga: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                {vgaTypes.map(v => <option key={v.value} value={v.value}>{v.label}</option>)}
                                            </select>
                                        </div>
                                    </div>
                                    {/* MK: High Availability Section */}
                                    <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h4 className="text-sm font-medium text-red-400">{t('highAvailability') || 'High Availability'}</h4>
                                            <label className="flex items-center gap-2 text-sm text-gray-300">
                                                <input type="checkbox" checked={config.ha_enabled} onChange={e => setConfig({...config, ha_enabled: e.target.checked})} className="rounded" />
                                                {t('enableHa') || 'Add to Proxmox Native HA'}
                                            </label>
                                        </div>
                                        {config.ha_enabled && (
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">{t('haGroup') || 'HA Group'}</label>
                                                <input type="text" value={config.ha_group} onChange={e => setConfig({...config, ha_group: e.target.value})}
                                                    placeholder={t('defaultGroup') || 'Default group (leave empty)'}
                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                            </div>
                                        )}
                                    </div>
                                    
                                    <div className="space-y-2">
                                        <label className="flex items-center gap-2 text-sm text-gray-300">
                                            <input type="checkbox" checked={config.agent} onChange={e => setConfig({...config, agent: e.target.checked})} className="rounded" />
                                            {t('enableQemuAgent')}
                                        </label>
                                        <label className="flex items-center gap-2 text-sm text-gray-300">
                                            <input type="checkbox" checked={config.onboot} onChange={e => setConfig({...config, onboot: e.target.checked})} className="rounded" />
                                            {t('startOnBoot')}
                                        </label>
                                        <label className="flex items-center gap-2 text-sm text-gray-300">
                                            <input type="checkbox" checked={config.start} onChange={e => setConfig({...config, start: e.target.checked})} className="rounded" />
                                            {t('startAfterCreate')}
                                        </label>
                                    </div>
                                </div>
                            );
                    }
                } else {
                    // LXC Container
                    switch(activeStep) {
                        case 0: // Allgemein
                            return (
                                <div className="space-y-4">
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">Node</label>
                                            <select value={config.node} onChange={e => setConfig({...config, node: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                {nodes.map(n => <option key={n} value={n}>{n}</option>)}
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">CT ID</label>
                                            <input type="number" value={config.vmid} onChange={e => setConfig({...config, vmid: e.target.value})}
                                                placeholder={nextVmid ? `Nächste: ${nextVmid}` : ''}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                        </div>
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">Hostname</label>
                                        <input type="text" value={config.name} onChange={e => setConfig({...config, name: e.target.value})}
                                            placeholder="my-container"
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                    </div>
                                </div>
                            );
                        case 1: // Template
                            return (
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">Template</label>
                                        <select value={config.template} onChange={e => setConfig({...config, template: e.target.value})}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                            <option value="">{t('selectTemplate')}</option>
                                            {templateList.filter(tpl => tpl.type === 'lxc').map(tpl => <option key={tpl.volid} value={tpl.volid}>{tpl.name}</option>)}
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('rootPassword')}</label>
                                        <input type="password" value={config.password} onChange={e => setConfig({...config, password: e.target.value})}
                                            placeholder="••••••••"
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                    </div>
                                    
                                    {/* SSH Public Keys */}
                                    <div>
                                        <div className="flex items-center justify-between mb-1">
                                            <label className="block text-sm text-gray-400">{t('sshPublicKeys')}</label>
                                            <label className="text-xs text-proxmox-orange cursor-pointer hover:text-orange-400">
                                                <input
                                                    type="file"
                                                    accept=".pub,.txt"
                                                    className="hidden"
                                                    onChange={(e) => {
                                                        const file = e.target.files[0];
                                                        if (file) {
                                                            const reader = new FileReader();
                                                            reader.onload = (event) => {
                                                                const content = event.target.result;
                                                                setConfig(prev => ({
                                                                    ...prev,
                                                                    ssh_public_keys: prev.ssh_public_keys 
                                                                        ? prev.ssh_public_keys + '\n' + content.trim()
                                                                        : content.trim()
                                                                }));
                                                            };
                                                            reader.readAsText(file);
                                                        }
                                                        e.target.value = '';
                                                    }}
                                                />
                                                📂 {t('loadSshKeyFile') || 'Load SSH Key File'}
                                            </label>
                                        </div>
                                        <textarea
                                            value={config.ssh_public_keys}
                                            onChange={e => setConfig({...config, ssh_public_keys: e.target.value})}
                                            placeholder="ssh-rsa AAAAB3... user@host"
                                            rows={3}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm font-mono resize-none"
                                        />
                                        <p className="text-xs text-gray-500 mt-1">{t('sshKeyHintMultiple') || 'One key per line. Paste or load from file.'}</p>
                                    </div>
                                </div>
                            );
                        case 2: // Ressourcen
                            return (
                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('cpuCoresLabel')}</label>
                                        <input type="number" min="1" max="128" value={config.cores} onChange={e => setConfig({...config, cores: parseInt(e.target.value)})}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">RAM</label>
                                        <div className="flex gap-2">
                                            <input type="number" min={config.memoryUnit === 'GB' ? 0.1 : 16} step={config.memoryUnit === 'GB' ? 0.25 : 64} 
                                                value={config.memoryUnit === 'GB' ? (config.memory / 1024) : config.memory} 
                                                onChange={e => {
                                                    const val = parseFloat(e.target.value) || 0;
                                                    setConfig({...config, memory: config.memoryUnit === 'GB' ? Math.round(val * 1024) : val});
                                                }}
                                                className="flex-1 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                            <select value={config.memoryUnit || 'MB'} onChange={e => setConfig({...config, memoryUnit: e.target.value})}
                                                className="w-20 px-2 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                <option value="MB">MB</option>
                                                <option value="GB">GB</option>
                                            </select>
                                        </div>
                                        <p className="text-xs text-gray-500 mt-1">
                                            {config.memoryUnit === 'GB' ? `${config.memory} MB` : `${(config.memory / 1024).toFixed(1)} GB`}
                                        </p>
                                    </div>
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">{t('swapMemory')}</label>
                                        <div className="flex gap-2">
                                            <input type="number" min={config.swapUnit === 'GB' ? 0 : 0} step={config.swapUnit === 'GB' ? 0.25 : 64} 
                                                value={config.swapUnit === 'GB' ? (config.swap / 1024) : config.swap} 
                                                onChange={e => {
                                                    const val = parseFloat(e.target.value) || 0;
                                                    setConfig({...config, swap: config.swapUnit === 'GB' ? Math.round(val * 1024) : val});
                                                }}
                                                className="flex-1 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                            <select value={config.swapUnit || 'MB'} onChange={e => setConfig({...config, swapUnit: e.target.value})}
                                                className="w-20 px-2 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
                                                <option value="MB">MB</option>
                                                <option value="GB">GB</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                            );
                        case 3: // Disk
                            // MK: Helper to render storage bar for LXC
                            const renderLxcStorageBar = (selectedStorage) => {
                                const storageInfo = storageList.find(s => s.storage === selectedStorage);
                                if (!storageInfo) return null;
                                const total = storageInfo.total || storageInfo.maxdisk || 0;
                                const used = storageInfo.used || storageInfo.disk || 0;
                                const avail = total - used;
                                if (total <= 0) return null;
                                const usedPercent = total > 0 ? (used / total) * 100 : 0;
                                const freeGB = (avail / 1024 / 1024 / 1024).toFixed(1);
                                return (
                                    <div className="mt-2">
                                        <div className="flex justify-between text-xs text-gray-500 mb-1">
                                            <span>{freeGB} GB {t('free')}</span>
                                            <span>{usedPercent.toFixed(0)}% {t('used')}</span>
                                        </div>
                                        <div className="h-1.5 bg-proxmox-dark rounded-full overflow-hidden">
                                            <div className={`h-full ${usedPercent > 90 ? 'bg-red-500' : usedPercent > 70 ? 'bg-yellow-500' : 'bg-green-500'}`}
                                                style={{ width: `${usedPercent}%` }} />
                                        </div>
                                    </div>
                                );
                            };
                            
                            return (
                                <div className="space-y-4">
                                    {/* MK: Root Filesystem */}
                                    <div className="p-4 bg-proxmox-dark/50 rounded-lg border border-proxmox-border">
                                        <h4 className="text-sm font-medium text-white mb-3">{t('rootFilesystem') || 'Root Filesystem'} (rootfs)</h4>
                                        <div className="grid grid-cols-3 gap-4">
                                            <div className="col-span-2">
                                                <label className="block text-xs text-gray-400 mb-1">Storage</label>
                                                <select value={config.storage} onChange={e => setConfig({...config, storage: e.target.value})}
                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                    {storageList.map(s => (
                                                        <option key={s.storage} value={s.storage}>
                                                            {s.storage} ({s.type || 'storage'})
                                                        </option>
                                                    ))}
                                                </select>
                                                {renderLxcStorageBar(config.storage)}
                                            </div>
                                            <div>
                                                <label className="block text-xs text-gray-400 mb-1">{t('size')} (GB)</label>
                                                <input type="number" min="1" value={config.disk_size} onChange={e => setConfig({...config, disk_size: e.target.value})}
                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {/* MK: Additional Mount Points */}
                                    {config.additional_disks.map((mp, idx) => (
                                        <div key={idx} className="p-4 bg-proxmox-dark/50 rounded-lg border border-proxmox-border">
                                            <div className="flex items-center justify-between mb-3">
                                                <h4 className="text-sm font-medium text-white">{t('mountPoint') || 'Mount Point'} {idx} (mp{idx})</h4>
                                                <button onClick={() => setConfig({...config, additional_disks: config.additional_disks.filter((_, i) => i !== idx)})}
                                                    className="p-1 text-red-400 hover:bg-red-500/20 rounded">
                                                    <Icons.Trash2 className="w-4 h-4" />
                                                </button>
                                            </div>
                                            <div className="grid grid-cols-4 gap-3">
                                                <div className="col-span-2">
                                                    <label className="block text-xs text-gray-400 mb-1">Storage</label>
                                                    <select value={mp.storage} onChange={e => {
                                                        const newMps = [...config.additional_disks];
                                                        newMps[idx] = {...mp, storage: e.target.value};
                                                        setConfig({...config, additional_disks: newMps});
                                                    }}
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm">
                                                        {storageList.map(s => <option key={s.storage} value={s.storage}>{s.storage} ({s.type || 'storage'})</option>)}
                                                    </select>
                                                    {renderLxcStorageBar(mp.storage)}
                                                </div>
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('size')} (GB)</label>
                                                    <input type="number" min="1" value={mp.size} onChange={e => {
                                                        const newMps = [...config.additional_disks];
                                                        newMps[idx] = {...mp, size: e.target.value};
                                                        setConfig({...config, additional_disks: newMps});
                                                    }}
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                </div>
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('path') || 'Path'}</label>
                                                    <input type="text" value={mp.path || ''} onChange={e => {
                                                        const newMps = [...config.additional_disks];
                                                        newMps[idx] = {...mp, path: e.target.value};
                                                        setConfig({...config, additional_disks: newMps});
                                                    }}
                                                        placeholder="/mnt/data"
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                    
                                    {/* MK: Add Mount Point Button */}
                                    <button onClick={() => setConfig({...config, additional_disks: [...config.additional_disks, {storage: config.storage, size: '8', path: '/mnt/data' + config.additional_disks.length}]})}
                                        className="w-full px-4 py-2 border-2 border-dashed border-proxmox-border rounded-lg text-gray-400 hover:text-white hover:border-proxmox-orange transition-colors">
                                        + {t('addMountPoint') || 'Add Mount Point'}
                                    </button>
                                </div>
                            );
                        case 4: // Netzwerk
                            return (
                                <div className="space-y-4">
                                    {/* Bridge Selection */}
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">Bridge / VNet</label>
                                            <select value={config.net_bridge} onChange={e => setConfig({...config, net_bridge: e.target.value})}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white">
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
                                                {bridgeList.length === 0 && <option value="vmbr0">vmbr0</option>}
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">VLAN Tag</label>
                                            <input type="text" value={config.net_tag} onChange={e => setConfig({...config, net_tag: e.target.value})}
                                                placeholder={t('optional') || 'optional'}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                        </div>
                                    </div>
                                    
                                    {/* MK: Advanced Network for LXC */}
                                    <div className="grid grid-cols-3 gap-4">
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('macAddress') || 'MAC Address'}</label>
                                            <input type="text" value={config.net_macaddr} onChange={e => setConfig({...config, net_macaddr: e.target.value})}
                                                placeholder={t('autoGenerate') || 'Auto-generate'}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">MTU</label>
                                            <input type="number" min="1" max="65520" value={config.net_mtu} onChange={e => setConfig({...config, net_mtu: e.target.value})}
                                                placeholder={t('inheritBridge') || 'Inherit'}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                        </div>
                                        <div>
                                            <label className="block text-sm text-gray-400 mb-1">{t('rateLimit') || 'Rate Limit'} (MB/s)</label>
                                            <input type="number" min="0" step="0.1" value={config.net_rate} onChange={e => setConfig({...config, net_rate: e.target.value})}
                                                placeholder={t('unlimited') || 'Unlimited'}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                        </div>
                                    </div>
                                    
                                    {/* IPv4 Configuration */}
                                    <div className="p-3 bg-proxmox-dark/50 rounded-lg border border-proxmox-border">
                                        <div className="flex items-center justify-between mb-3">
                                            <span className="text-sm font-medium text-white">IPv4</span>
                                            <select 
                                                value={config.net_ip_type} 
                                                onChange={e => setConfig({...config, net_ip_type: e.target.value, net_ip: e.target.value === 'dhcp' ? 'dhcp' : ''})}
                                                className="px-2 py-1 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm"
                                            >
                                                <option value="dhcp">DHCP</option>
                                                <option value="static">Static</option>
                                                <option value="manual">{t('manual') || 'Manual'}</option>
                                            </select>
                                        </div>
                                        {config.net_ip_type === 'static' && (
                                            <div className="grid grid-cols-2 gap-3">
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('ipAddress') || 'IP Address'}</label>
                                                    <input type="text" value={config.net_ip} onChange={e => setConfig({...config, net_ip: e.target.value})}
                                                        placeholder="192.168.1.100/24"
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                </div>
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">Gateway</label>
                                                    <input type="text" value={config.net_gw} onChange={e => setConfig({...config, net_gw: e.target.value})}
                                                        placeholder="192.168.1.1"
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                    
                                    {/* IPv6 Configuration */}
                                    <div className="p-3 bg-proxmox-dark/50 rounded-lg border border-proxmox-border">
                                        <div className="flex items-center justify-between mb-3">
                                            <span className="text-sm font-medium text-white">IPv6</span>
                                            <select 
                                                value={config.net_ip6_type} 
                                                onChange={e => setConfig({...config, net_ip6_type: e.target.value, net_ip6: e.target.value === 'dhcp' ? 'dhcp' : e.target.value === 'slaac' ? 'auto' : ''})}
                                                className="px-2 py-1 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm"
                                            >
                                                <option value="dhcp">DHCP</option>
                                                <option value="slaac">SLAAC</option>
                                                <option value="static">Static</option>
                                                <option value="manual">{t('manual') || 'Manual'}</option>
                                            </select>
                                        </div>
                                        {config.net_ip6_type === 'static' && (
                                            <div className="grid grid-cols-2 gap-3">
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">{t('ipAddress') || 'IP Address'}</label>
                                                    <input type="text" value={config.net_ip6} onChange={e => setConfig({...config, net_ip6: e.target.value})}
                                                        placeholder="2001:db8::100/64"
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                </div>
                                                <div>
                                                    <label className="block text-xs text-gray-400 mb-1">Gateway</label>
                                                    <input type="text" value={config.net_gw6} onChange={e => setConfig({...config, net_gw6: e.target.value})}
                                                        placeholder="2001:db8::1"
                                                        className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                    
                                    {/* Network Options */}
                                    <div className="flex flex-wrap gap-4">
                                        <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                                            <input type="checkbox" checked={config.net_firewall} onChange={e => setConfig({...config, net_firewall: e.target.checked})} className="rounded" />
                                            {t('enableFirewall')}
                                        </label>
                                        <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                                            <input type="checkbox" checked={config.net_disconnected} onChange={e => setConfig({...config, net_disconnected: e.target.checked})} className="rounded" />
                                            {t('disconnected') || 'Disconnected'}
                                        </label>
                                    </div>
                                </div>
                            );
                        case 5: // Optionen
                            return (
                                <div className="space-y-4">
                                    {/* MK: High Availability Section for LXC */}
                                    <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h4 className="text-sm font-medium text-red-400">{t('highAvailability') || 'High Availability'}</h4>
                                            <label className="flex items-center gap-2 text-sm text-gray-300">
                                                <input type="checkbox" checked={config.ha_enabled} onChange={e => setConfig({...config, ha_enabled: e.target.checked})} className="rounded" />
                                                {t('enableHa') || 'Add to Proxmox Native HA'}
                                            </label>
                                        </div>
                                        {config.ha_enabled && (
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">{t('haGroup') || 'HA Group'}</label>
                                                <input type="text" value={config.ha_group} onChange={e => setConfig({...config, ha_group: e.target.value})}
                                                    placeholder={t('defaultGroup') || 'Default group (leave empty)'}
                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white" />
                                            </div>
                                        )}
                                    </div>
                                    
                                    {/* Container Options */}
                                    <div className="space-y-2">
                                        <label className="flex items-center gap-2 text-sm text-gray-300">
                                            <input type="checkbox" checked={config.unprivileged} onChange={e => setConfig({...config, unprivileged: e.target.checked})} className="rounded" />
                                            Unprivileged Container ({t('recommended') || 'recommended'})
                                        </label>
                                        <label className="flex items-center gap-2 text-sm text-gray-300">
                                            <input type="checkbox" checked={config.nesting} onChange={e => setConfig({...config, nesting: e.target.checked})} className="rounded" />
                                            Nesting ({t('dockerSupport') || 'Docker support'})
                                        </label>
                                        <label className="flex items-center gap-2 text-sm text-gray-300">
                                            <input type="checkbox" checked={config.onboot} onChange={e => setConfig({...config, onboot: e.target.checked})} className="rounded" />
                                            {t('startOnBoot')}
                                        </label>
                                        <label className="flex items-center gap-2 text-sm text-gray-300">
                                            <input type="checkbox" checked={config.start} onChange={e => setConfig({...config, start: e.target.checked})} className="rounded" />
                                            {t('startAfterCreate')}
                                        </label>
                                    </div>
                                    
                                    {/* DNS Settings */}
                                    <div className="p-3 bg-proxmox-dark/50 rounded-lg border border-proxmox-border">
                                        <h4 className="text-sm font-medium text-white mb-3">DNS</h4>
                                        <div className="space-y-3">
                                            <div>
                                                <label className="block text-xs text-gray-400 mb-1">{t('dnsDomain') || 'DNS Domain'}</label>
                                                <input type="text" value={config.dns_domain} onChange={e => setConfig({...config, dns_domain: e.target.value})}
                                                    placeholder={t('useHostSettings') || 'Use host settings'}
                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                            </div>
                                            <div>
                                                <label className="block text-xs text-gray-400 mb-1">{t('dnsServers') || 'DNS Servers'}</label>
                                                <input type="text" value={config.dns_servers} onChange={e => setConfig({...config, dns_servers: e.target.value})}
                                                    placeholder={t('useHostSettings') || 'Use host settings (e.g. 8.8.8.8 1.1.1.1)'}
                                                    className="w-full px-2 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-white text-sm" />
                                                <p className="text-xs text-gray-500 mt-1">{t('dnsServersHint') || 'Space-separated list of DNS servers'}</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            );
                    }
                }
            };

            return (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80">
                    <div className="w-full max-w-2xl bg-proxmox-card border border-proxmox-border rounded-xl shadow-2xl animate-scale-in overflow-hidden">
                        {/* Header */}
                        <div className="flex items-center justify-between px-6 py-4 border-b border-proxmox-border bg-proxmox-dark">
                            <div className="flex items-center gap-3">
                                <div className={`p-2 rounded-lg ${isQemu ? 'bg-blue-500/10' : 'bg-purple-500/10'}`}>
                                    {isQemu ? <Icons.VM /> : <Icons.Container />}
                                </div>
                                <h2 className="font-semibold text-white">
                                    {isQemu ? t('createVm') : t('createContainer')}
                                </h2>
                            </div>
                            <button onClick={onClose} className="p-2 hover:bg-proxmox-hover rounded-lg text-gray-400 hover:text-white">
                                <Icons.X />
                            </button>
                        </div>

                        {/* No nodes warning */}
                        {nodes.length === 0 && (
                            <div className="p-4 bg-yellow-500/10 border-b border-yellow-500/30">
                                <p className="text-yellow-400 text-sm">
                                    ⚠️ {t('noNodesAvailable') || 'No nodes available. Please wait for cluster data to load.'}
                                </p>
                            </div>
                        )}
                        
                        {/* Debug info */}
                        {storageList.length === 0 && config.node && (
                            <div className="px-6 pt-2">
                                <p className="text-xs text-gray-500">
                                    {t('loadingStorage') || 'Lade Storage-Liste...'} (Node: {config.node})
                                </p>
                            </div>
                        )}

                        {/* Steps Navigation */}
                        <div className="flex border-b border-proxmox-border bg-proxmox-dark/50">
                            {steps.map((step, idx) => (
                                <button
                                    key={step}
                                    onClick={() => setActiveStep(idx)}
                                    className={`flex-1 px-4 py-3 text-sm font-medium transition-colors ${
                                        activeStep === idx
                                            ? 'text-proxmox-orange border-b-2 border-proxmox-orange'
                                            : 'text-gray-400 hover:text-white'
                                    }`}
                                >
                                    {step}
                                </button>
                            ))}
                        </div>

                        {/* Content */}
                        <div className="p-6 min-h-[300px]">
                            {renderStepContent()}
                        </div>

                        {/* Footer */}
                        <div className="flex items-center justify-between px-6 py-4 border-t border-proxmox-border bg-proxmox-dark">
                            <button
                                onClick={() => setActiveStep(Math.max(0, activeStep - 1))}
                                disabled={activeStep === 0}
                                className="px-4 py-2 text-gray-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {t('back')}
                            </button>
                            <div className="flex gap-3">
                                <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">
                                    {t('cancel')}
                                </button>
                                {activeStep < steps.length - 1 ? (
                                    <button
                                        onClick={() => setActiveStep(activeStep + 1)}
                                        className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600"
                                    >
                                        {t('next')}
                                    </button>
                                ) : (
                                    <button
                                        onClick={handleCreate}
                                        disabled={loading || (!isQemu && !config.template)}
                                        className="flex items-center gap-2 px-4 py-2 bg-green-600 rounded-lg text-white hover:bg-green-700 disabled:opacity-50"
                                    >
                                        {loading && <Icons.RotateCw />}
                                        {isQemu ? t('createVm') : t('createContainer')}
                                    </button>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            );
        }

        // Add Cluster Modal
        // LW: Wizard for adding new Proxmox clusters
        // Defaults are pretty sensible, most users just need host + credentials
        function AddClusterModal({ isOpen, onClose, onSubmit, onAddPBS, onAddVMware, loading, error, initialType = 'proxmox' }) {
            const { t } = useTranslation();
            const [connectionType, setConnectionType] = useState(initialType);
            
            // Sync with initialType when modal opens with different type
            useEffect(() => {
                if (isOpen) setConnectionType(initialType);
            }, [isOpen, initialType]);
            
            // Proxmox config
            const [config, setConfig] = useState({
                name: '', host: '', user: 'root@pam', pass: '',
                ssl_verification: false, migration_threshold: 20, check_interval: 300,
                auto_migrate: true, balance_containers: false, balance_local_disks: false,
                dry_run: false, ssh_key: '',
            });
            const [showSshSettings, setShowSshSettings] = useState(false);
            
            // PBS config
            const [pbsConfig, setPbsConfig] = useState({
                name: '', host: '', port: 8007, user: 'root@pam', password: '',
                api_token_id: '', api_token_secret: '', fingerprint: '',
                ssl_verify: false, linked_clusters: [], notes: '',
            });
            
            // VMware config
            const [vmwConfig, setVmwConfig] = useState({
                name: '', host: '', port: 443, username: 'root', password: '',
                ssl_verify: false, notes: '',
            });

            if (!isOpen) return null;

            const handleSubmit = (e) => {
                e.preventDefault();
                if (connectionType === 'proxmox') onSubmit(config);
                else if (connectionType === 'pbs') onAddPBS(pbsConfig);
                else if (connectionType === 'vmware') onAddVMware(vmwConfig);
            };

            return (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 modal-backdrop bg-black/60" onClick={onClose}>
                    <div 
                        className="w-full max-w-lg bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl animate-scale-in overflow-hidden max-h-[90vh] overflow-y-auto"
                        onClick={e => e.stopPropagation()}
                    >
                        <div className="p-6 border-b border-proxmox-border">
                            <h2 className="text-xl font-bold text-white">{t('addCluster')}</h2>
                            <div className="flex gap-2 mt-3">
                                {[
                                    { id: 'proxmox', label: 'Proxmox VE', icon: Icons.Server, active: 'bg-orange-500/20 text-orange-400 border-orange-500/40', inactive: 'bg-proxmox-dark text-gray-500 border-transparent hover:text-gray-300 hover:border-proxmox-border' },
                                    { id: 'pbs', label: 'PBS', icon: Icons.Shield, active: 'bg-blue-500/20 text-blue-400 border-blue-500/40', inactive: 'bg-proxmox-dark text-gray-500 border-transparent hover:text-gray-300 hover:border-proxmox-border' },
                                    { id: 'vmware', label: 'ESXi / vCenter', icon: Icons.Cloud, active: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40', inactive: 'bg-proxmox-dark text-gray-500 border-transparent hover:text-gray-300 hover:border-proxmox-border' },
                                ].map(tab => (
                                    <button
                                        key={tab.id}
                                        onClick={() => setConnectionType(tab.id)}
                                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                                            connectionType === tab.id ? tab.active : tab.inactive
                                        }`}
                                    >
                                        <tab.icon className="w-3.5 h-3.5" />
                                        {tab.label}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {error && (
                            <div className="mx-6 mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                                {error}
                            </div>
                        )}

                        <form onSubmit={handleSubmit} className="p-6 space-y-5">
                            {/* ===== PROXMOX VE FORM ===== */}
                            {connectionType === 'proxmox' && (<>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('clusterName')}</label>
                                    <input type="text" value={config.name} onChange={e => setConfig({...config, name: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors"
                                        placeholder="Production Cluster" />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('host')}</label>
                                    <input type="text" value={config.host} onChange={e => setConfig({...config, host: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors"
                                        placeholder="proxmox.example.com" />
                                </div>
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('username')}</label>
                                    <input type="text" value={config.user} onChange={e => setConfig({...config, user: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors"
                                        placeholder="root@pam or user@pam!tokenid" />
                                    <p className="mt-1 text-xs text-gray-500">{t('apiTokenHint') || 'For API tokens use: user@realm!tokenid'}</p>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('passwordOrToken') || t('password')}</label>
                                    <input type="password" value={config.pass} onChange={e => setConfig({...config, pass: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors"
                                        placeholder={config.user.includes('!') ? 'Token Secret' : 'Password'} />
                                </div>
                            </div>
                            
                            {config.user.includes('!') && (
                                <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                    <div className="flex items-start gap-3">
                                        <Icons.AlertTriangle className="w-5 h-5 text-yellow-400 shrink-0 mt-0.5" />
                                        <div>
                                            <p className="font-medium text-yellow-200">{t('apiTokenWarningTitle') || 'API Token Authentication'}</p>
                                            <p className="text-sm text-yellow-300/80 mt-1">{t('apiTokenWarningDesc') || 'Using API tokens is supported but not all features will work correctly.'}</p>
                                        </div>
                                    </div>
                                </div>
                            )}

                            <div className="pt-4 border-t border-proxmox-border">
                                <button type="button" onClick={() => setShowSshSettings(!showSshSettings)}
                                    className="flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors">
                                    <Icons.ChevronRight className={`w-3 h-3 transform transition-transform ${showSshSettings ? 'rotate-90' : ''}`} />
                                    {t('sshKeyOptional') || 'SSH Key (Optional)'}
                                </button>
                                {showSshSettings && (
                                    <div className="mt-4 space-y-4 p-4 bg-proxmox-dark/50 rounded-lg">
                                        <p className="text-xs text-gray-400">{t('sshKeyExplanation') || 'SSH features use your login credentials automatically. Only add a key here if password authentication is disabled on your nodes.'}</p>
                                        <textarea value={config.ssh_key} onChange={e => setConfig({...config, ssh_key: e.target.value})}
                                            className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors font-mono text-xs"
                                            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" rows={4} />
                                    </div>
                                )}
                            </div>

                            <div className="space-y-4 pt-4 border-t border-proxmox-border">
                                <Slider label={t('migrationThreshold')} description={t('migrationThresholdDesc')} value={config.migration_threshold}
                                    onChange={v => setConfig({...config, migration_threshold: v})} min={5} max={100} />
                                <Slider label={t('checkInterval')} description={t('checkIntervalDesc')} value={config.check_interval}
                                    onChange={v => setConfig({...config, check_interval: v})} min={60} max={3600} step={60} unit="s" />
                            </div>

                            <div className="flex flex-wrap gap-4 pt-4 border-t border-proxmox-border">
                                <Toggle checked={config.ssl_verification} onChange={v => setConfig({...config, ssl_verification: v})} label={t('sslVerification')} />
                                <Toggle checked={config.auto_migrate} onChange={v => setConfig({...config, auto_migrate: v})} label={t('autoMigrate')} />
                                <Toggle checked={config.dry_run} onChange={v => setConfig({...config, dry_run: v})} label={t('dryRunShort')} />
                            </div>

                            <div className="pt-4 border-t border-proxmox-border">
                                <div className="flex items-start gap-3">
                                    <Toggle checked={config.balance_containers} onChange={v => setConfig({...config, balance_containers: v})} label={t('balanceContainers')} />
                                </div>
                                <div className="flex items-start gap-3 pt-3 mt-3 border-t border-gray-700/50">
                                    <Toggle checked={config.balance_local_disks} onChange={v => setConfig({...config, balance_local_disks: v})} label={t('balanceLocalDisks')} />
                                </div>
                                <div className="text-xs text-gray-500 mt-1">{t('balanceLocalDisksDesc')}</div>
                            </div>
                            </>)}

                            {/* ===== PBS FORM ===== */}
                            {connectionType === 'pbs' && (<>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('name')}</label>
                                    <input type="text" value={pbsConfig.name} onChange={e => setPbsConfig({...pbsConfig, name: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-400 transition-colors"
                                        placeholder="Backup Server 1" />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('host')}</label>
                                    <input type="text" value={pbsConfig.host} onChange={e => setPbsConfig({...pbsConfig, host: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-400 transition-colors"
                                        placeholder="pbs.example.com" />
                                </div>
                            </div>
                            <div className="grid grid-cols-3 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('username')}</label>
                                    <input type="text" value={pbsConfig.user} onChange={e => setPbsConfig({...pbsConfig, user: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-400 transition-colors"
                                        placeholder="root@pam" />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('password')}</label>
                                    <input type="password" value={pbsConfig.password} onChange={e => setPbsConfig({...pbsConfig, password: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-400 transition-colors"
                                        placeholder="Password" />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">Port</label>
                                    <input type="number" value={pbsConfig.port} onChange={e => setPbsConfig({...pbsConfig, port: parseInt(e.target.value) || 8007})}
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white focus:outline-none focus:border-blue-400 transition-colors" />
                                </div>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-300 mb-2">Fingerprint ({t('optional') || 'Optional'})</label>
                                <input type="text" value={pbsConfig.fingerprint} onChange={e => setPbsConfig({...pbsConfig, fingerprint: e.target.value})}
                                    className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-400 transition-colors font-mono text-xs"
                                    placeholder="XX:XX:XX:..." />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-300 mb-2">{t('notes') || 'Notes'} ({t('optional') || 'Optional'})</label>
                                <input type="text" value={pbsConfig.notes} onChange={e => setPbsConfig({...pbsConfig, notes: e.target.value})}
                                    className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-400 transition-colors"
                                    placeholder="Backup for production cluster" />
                            </div>
                            </>)}

                            {/* ===== VMWARE FORM ===== */}
                            {connectionType === 'vmware' && (<>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('name')}</label>
                                    <input type="text" value={vmwConfig.name} onChange={e => setVmwConfig({...vmwConfig, name: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-emerald-400 transition-colors"
                                        placeholder="ESXi Host 1" />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('host')}</label>
                                    <input type="text" value={vmwConfig.host} onChange={e => setVmwConfig({...vmwConfig, host: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-emerald-400 transition-colors"
                                        placeholder="esxi.example.com" />
                                </div>
                            </div>
                            <div className="grid grid-cols-3 gap-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('username')}</label>
                                    <input type="text" value={vmwConfig.username} onChange={e => setVmwConfig({...vmwConfig, username: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-emerald-400 transition-colors"
                                        placeholder="root" />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">{t('password')}</label>
                                    <input type="password" value={vmwConfig.password} onChange={e => setVmwConfig({...vmwConfig, password: e.target.value})} required
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-emerald-400 transition-colors"
                                        placeholder="Password" />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">Port</label>
                                    <input type="number" value={vmwConfig.port} onChange={e => setVmwConfig({...vmwConfig, port: parseInt(e.target.value) || 443})}
                                        className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white focus:outline-none focus:border-emerald-400 transition-colors" />
                                </div>
                            </div>
                            <div className="flex items-center gap-4">
                                <Toggle checked={vmwConfig.ssl_verify} onChange={v => setVmwConfig({...vmwConfig, ssl_verify: v})} label={t('sslVerification')} />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-300 mb-2">{t('notes') || 'Notes'} ({t('optional') || 'Optional'})</label>
                                <input type="text" value={vmwConfig.notes} onChange={e => setVmwConfig({...vmwConfig, notes: e.target.value})}
                                    className="w-full px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-emerald-400 transition-colors"
                                    placeholder="Production ESXi host" />
                            </div>
                            </>)}

                            <div className="flex gap-3 pt-4 border-t border-proxmox-border">
                                <button type="button" onClick={onClose}
                                    className="flex-1 px-4 py-2.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-300 font-medium hover:bg-proxmox-hover transition-colors">
                                    {t('cancel')}
                                </button>
                                <button type="submit" disabled={loading}
                                    className={`flex-1 px-4 py-2.5 rounded-lg text-white font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                                        connectionType === 'pbs' ? 'bg-blue-500 hover:bg-blue-600' 
                                        : connectionType === 'vmware' ? 'bg-emerald-500 hover:bg-emerald-600'
                                        : 'bg-proxmox-orange hover:bg-orange-600'
                                    }`}>
                                    {loading ? t('connecting') : connectionType === 'pbs' ? (t('addPbsServer') || 'Add Backup Server') 
                                        : connectionType === 'vmware' ? (t('addVmwareServer') || 'Add VMware') 
                                        : t('addCluster')}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            );
        }

        // User Profile Modal with Password Change and 2FA Setup
        function UserProfileModal({ isOpen, onClose, addToast }) {
            const { t } = useTranslation();
            const { getAuthHeaders, user, updatePreferences } = useAuth();
            const [activeTab, setActiveTab] = useState('appearance');
            const [loading, setLoading] = useState(false);
            const [selectedTheme, setSelectedTheme] = useState(user?.theme || 'proxmoxDark');
            
            // Password change
            const [currentPassword, setCurrentPassword] = useState('');
            const [newPassword, setNewPassword] = useState('');
            const [confirmPassword, setConfirmPassword] = useState('');
            
            // 2FA setup
            const [twoFAStatus, setTwoFAStatus] = useState({ enabled: false, available: false });
            const [setupData, setSetupData] = useState(null);
            const [totpCode, setTotpCode] = useState('');
            const [disablePassword, setDisablePassword] = useState('');
            
            // MK: Feb 2026 - API Token management
            const [tokens, setTokens] = useState([]);
            const [tokensLoading, setTokensLoading] = useState(false);
            const [newTokenName, setNewTokenName] = useState('');
            const [newTokenRole, setNewTokenRole] = useState('');
            const [newTokenExpiry, setNewTokenExpiry] = useState('');
            const [createdToken, setCreatedToken] = useState(null);
            const [tokenCopied, setTokenCopied] = useState(false);
            
            // Password Policy state - NS Jan 2026
            const [passwordPolicy, setPasswordPolicy] = useState({
                min_length: 8,
                require_uppercase: true,
                require_lowercase: true,
                require_numbers: true,
                require_special: false
            });
            
            // Generate password policy hint text
            const getPasswordPolicyHint = () => {
                const hints = [];
                hints.push(`${t('minChars') || 'Min.'} ${passwordPolicy.min_length} ${t('characters') || 'characters'}`);
                if (passwordPolicy.require_uppercase) hints.push(t('uppercase') || 'uppercase');
                if (passwordPolicy.require_lowercase) hints.push(t('lowercase') || 'lowercase');
                if (passwordPolicy.require_numbers) hints.push(t('numbers') || 'number');
                if (passwordPolicy.require_special) hints.push(t('specialChar') || 'special char');
                return hints.join(', ');
            };
            
            // Fetch password policy
            const fetchPasswordPolicy = async () => {
                try {
                    const r = await fetch(`${API_URL}/password-policy`, { credentials: 'include' });
                    if (r.ok) {
                        const data = await r.json();
                        setPasswordPolicy(data);
                    }
                } catch (e) {
                    console.error('Failed to fetch password policy:', e);
                }
            };
            
            useEffect(() => {
                if (isOpen) {
                    fetch2FAStatus();
                    fetchPasswordPolicy();
                    fetchTokens();  // MK: Load API tokens
                }
            }, [isOpen]);
            
            // LW: Feb 2026 - API Token management functions
            const fetchTokens = async () => {
                setTokensLoading(true);
                try {
                    const response = await fetch(`${API_URL}/auth/tokens`, {
                        credentials: 'include',
                        headers: getAuthHeaders()
                    });
                    if (response.ok) {
                        const data = await response.json();
                        setTokens(data.tokens || []);
                    }
                } catch (e) { console.error('fetchTokens error:', e); }
                finally { setTokensLoading(false); }
            };
            
            const createToken = async () => {
                if (!newTokenName.trim()) return;
                setLoading(true);
                try {
                    const body = { name: newTokenName.trim() };
                    if (newTokenRole) body.role = newTokenRole;
                    if (newTokenExpiry) body.expires_days = parseInt(newTokenExpiry);
                    
                    const response = await fetch(`${API_URL}/auth/tokens`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify(body)
                    });
                    const data = await response.json();
                    if (data.success) {
                        setCreatedToken(data.token);
                        setNewTokenName(''); setNewTokenRole(''); setNewTokenExpiry('');
                        fetchTokens();
                        if (addToast) addToast('Token created - copy it now, it won\'t be shown again!', 'warning');
                    } else {
                        if (addToast) addToast(data.error || 'Failed to create token', 'error');
                    }
                } catch (e) { if (addToast) addToast('Network error', 'error'); }
                finally { setLoading(false); }
            };
            
            const revokeToken = async (tokenId) => {
                try {
                    const response = await fetch(`${API_URL}/auth/tokens/${tokenId}`, {
                        method: 'DELETE',
                        credentials: 'include',
                        headers: getAuthHeaders()
                    });
                    if (response.ok) {
                        fetchTokens();
                        if (addToast) addToast('Token revoked', 'success');
                    }
                } catch (e) { if (addToast) addToast('Failed to revoke token', 'error'); }
            };
            
            const copyToken = (token) => {
                navigator.clipboard.writeText(token).then(() => {
                    setTokenCopied(true);
                    setTimeout(() => setTokenCopied(false), 3000);
                });
            };
            
            const fetch2FAStatus = async () => {
                try {
                    const response = await fetch(`${API_URL}/auth/2fa/status`, {
                        credentials: 'include',  // MK: Fix - need cookies for session auth
                        headers: getAuthHeaders()
                    });
                    if (response && response.ok) {
                        setTwoFAStatus(await response.json());
                    }
                } catch (err) {
                    console.error('fetching 2FA status:', err);
                }
            };
            
            const handleChangePassword = async (e) => {
                e.preventDefault();
                if (newPassword !== confirmPassword) {
                    addToast(t('passwordsDoNotMatch'), 'error');
                    return;
                }
                if (newPassword.length < 4) {
                    addToast(t('passwordTooShort'), 'error');
                    return;
                }
                
                setLoading(true);
                try {
                    const response = await fetch(`${API_URL}/auth/change-password`, {
                        method: 'POST',
                        credentials: 'include',  // MK: Fix - need cookies for session auth
                        headers: {
                            'Content-Type': 'application/json',
                            ...getAuthHeaders()
                        },
                        body: JSON.stringify({
                            current_password: currentPassword,
                            new_password: newPassword
                        })
                    });
                    
                    if (response && response.ok) {
                        addToast(t('passwordResetSuccess'), 'success');
                        setCurrentPassword('');
                        setNewPassword('');
                        setConfirmPassword('');
                    } else {
                        const data = await response.json();
                        addToast(data.error || 'Error', 'error');
                    }
                } catch (err) {
                    addToast(t('connectionError'), 'error');
                }
                setLoading(false);
            };
            
            const handleSetup2FA = async () => {
                setLoading(true);
                try {
                    const response = await fetch(`${API_URL}/auth/2fa/setup`, {
                        method: 'POST',
                        credentials: 'include',  // MK: Fix - need cookies for session auth
                        headers: getAuthHeaders()
                    });
                    
                    if (response && response.ok) {
                        setSetupData(await response.json());
                    } else {
                        const data = await response.json();
                        addToast(data.error || 'Error', 'error');
                    }
                } catch (err) {
                    addToast(t('connectionError'), 'error');
                }
                setLoading(false);
            };
            
            const handleVerify2FA = async () => {
                if (totpCode.length !== 6) return;
                
                setLoading(true);
                try {
                    const response = await fetch(`${API_URL}/auth/2fa/verify`, {
                        method: 'POST',
                        credentials: 'include',  // MK: Fix - need cookies for session auth
                        headers: {
                            'Content-Type': 'application/json',
                            ...getAuthHeaders()
                        },
                        body: JSON.stringify({ code: totpCode })
                    });
                    
                    if (response && response.ok) {
                        addToast(t('twoFactorEnabled'), 'success');
                        setSetupData(null);
                        setTotpCode('');
                        fetch2FAStatus();
                    } else {
                        const data = await response.json();
                        addToast(data.error || t('invalid2FACode'), 'error');
                    }
                } catch (err) {
                    addToast(t('connectionError'), 'error');
                }
                setLoading(false);
            };
            
            const handleDisable2FA = async () => {
                if (!disablePassword) {
                    addToast(t('currentPassword') + ' required', 'error');
                    return;
                }
                
                setLoading(true);
                try {
                    const response = await fetch(`${API_URL}/auth/2fa/disable`, {
                        method: 'POST',
                        credentials: 'include',  // MK: Fix - need cookies for session auth
                        headers: {
                            'Content-Type': 'application/json',
                            ...getAuthHeaders()
                        },
                        body: JSON.stringify({ password: disablePassword })
                    });
                    
                    if (response && response.ok) {
                        addToast(t('twoFactorDisabled'), 'success');
                        setDisablePassword('');
                        fetch2FAStatus();
                    } else {
                        const data = await response.json();
                        addToast(data.error || 'Error', 'error');
                    }
                } catch (err) {
                    addToast(t('connectionError'), 'error');
                }
                setLoading(false);
            };
            
            if (!isOpen) return null;
            
            return(
                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/80" onClick={onClose}>
                    <div 
                        className="w-full max-w-2xl max-h-[90vh] bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl overflow-hidden flex flex-col"
                        onClick={e => e.stopPropagation()}
                    >
                        {/* Header */}
                        <div className="flex items-center justify-between p-6 border-b border-proxmox-border">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-full bg-proxmox-orange/20 flex items-center justify-center text-proxmox-orange font-semibold">
                                    {user?.username?.[0]?.toUpperCase() || 'U'}
                                </div>
                                <div>
                                    <h2 className="text-xl font-bold text-white">{t('myProfile')}</h2>
                                    <p className="text-sm text-gray-400">{user?.display_name || user?.username}</p>
                                </div>
                            </div>
                            <button onClick={onClose} className="p-2 rounded-lg hover:bg-proxmox-dark text-gray-400 hover:text-white">
                                <Icons.X />
                            </button>
                        </div>
                        
                        {/* Tabs */}
                        <div className="flex border-b border-proxmox-border">
                            <button
                                onClick={() => setActiveTab('appearance')}
                                className={`flex-1 px-4 py-3 text-sm font-medium transition-colors flex items-center justify-center gap-2 ${
                                    activeTab === 'appearance' 
                                        ? 'text-proxmox-orange border-b-2 border-proxmox-orange' 
                                        : 'text-gray-400 hover:text-white'
                                }`}
                            >
                                <Icons.Palette />
                                {t('appearance') || 'Appearance'}
                            </button>
                            <button
                                onClick={() => setActiveTab('security')}
                                className={`flex-1 px-4 py-3 text-sm font-medium transition-colors flex items-center justify-center gap-2 ${
                                    activeTab === 'security' 
                                        ? 'text-proxmox-orange border-b-2 border-proxmox-orange' 
                                        : 'text-gray-400 hover:text-white'
                                }`}
                            >
                                <Icons.Lock />
                                {t('security')}
                            </button>
                            <button
                                onClick={() => setActiveTab('tokens')}
                                className={`flex-1 px-4 py-3 text-sm font-medium transition-colors flex items-center justify-center gap-2 ${
                                    activeTab === 'tokens' 
                                        ? 'text-proxmox-orange border-b-2 border-proxmox-orange' 
                                        : 'text-gray-400 hover:text-white'
                                }`}
                            >
                                <Icons.Key />
                                API Tokens
                            </button>
                        </div>
                        
                        {/* Content */}
                        <div className="flex-1 overflow-auto p-6">
                            {/* Appearance Tab */}
                            {activeTab === 'appearance' && (
                                <div className="space-y-6">
                                    <div>
                                        <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
                                            <Icons.Palette />
                                            {t('chooseTheme') || 'Choose Your Theme'}
                                        </h3>
                                        <p className="text-sm text-gray-400 mb-4">
                                            {t('themePersonal') || 'Select a theme that suits your style. This setting is personal and only affects your account.'}
                                        </p>
                                    </div>
                                    
                                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                                        {Object.entries(PEGAPROX_THEMES).map(([key, theme]) => {
                                            const isActive = (user?.theme || 'proxmoxDark') === key;
                                            return (
                                                <button
                                                    key={key}
                                                    onClick={async () => {
                                                        setSelectedTheme(key);
                                                        const result = await updatePreferences({ theme: key });
                                                        if (result.success) {
                                                            addToast(`${t('themeChanged') || 'Theme changed to'} ${theme.name}`, 'success');
                                                        } else {
                                                            addToast(t('themeChangeFailed') || 'Failed to save theme', 'error');
                                                        }
                                                    }}
                                                    className={`p-3 rounded-xl border-2 transition-all hover:scale-105 ${
                                                        isActive 
                                                            ? 'border-proxmox-orange ring-2 ring-proxmox-orange/30' 
                                                            : 'border-proxmox-border hover:border-gray-500'
                                                    }`}
                                                    title={theme.description || theme.name}
                                                >
                                                    <div 
                                                        className="h-16 rounded-lg mb-2 relative overflow-hidden"
                                                        style={{ 
                                                            background: theme.colors.darker,
                                                            border: `1px solid ${theme.colors.border}`
                                                        }}
                                                    >
                                                        <div className="absolute left-0 top-0 bottom-0 w-4" style={{ background: theme.colors.dark }} />
                                                        <div 
                                                            className="absolute right-2 top-2 bottom-2 left-6 rounded"
                                                            style={{ 
                                                                background: theme.colors.card,
                                                                border: `1px solid ${theme.colors.border}`
                                                            }}
                                                        >
                                                            <div 
                                                                className="w-3/4 h-1.5 rounded-full m-1.5"
                                                                style={{ background: theme.colors.primary }}
                                                            />
                                                        </div>
                                                        {isActive && (
                                                            <div className="absolute top-1 right-1 bg-proxmox-orange rounded-full p-0.5">
                                                                <Icons.Check className="w-3 h-3 text-white" />
                                                            </div>
                                                        )}
                                                    </div>
                                                    <div className="flex items-center justify-center gap-1.5">
                                                        <span className="text-lg">{theme.icon}</span>
                                                        <span className="text-xs font-medium">{theme.name}</span>
                                                    </div>
                                                </button>
                                            );
                                        })}
                                    </div>
                                    
                                    {/* LW: Feb 2026 - Layout Selector (Modern vs Corporate) */}
                                    <div className="pt-4 border-t border-proxmox-border">
                                        <h3 className="text-sm font-semibold text-white mb-1 flex items-center gap-2">
                                            <Icons.Grid className="w-4 h-4" />
                                            {t('layoutStyle') || 'Layout Style'}
                                        </h3>
                                        <p className="text-xs text-gray-400 mb-3">
                                            {t('layoutStyleDesc') || 'Choose between modern dashboard or corporate enterprise style.'}
                                        </p>
                                        <div className="grid grid-cols-2 gap-3">
                                            {/* Modern layout card */}
                                            <button
                                                onClick={async () => {
                                                    const result = await updatePreferences({ ui_layout: 'modern' });
                                                    if (result.success) addToast(`${t('layoutStyle')}: ${t('layoutModern') || 'Modern'}`, 'success');
                                                }}
                                                className={`p-3 rounded-xl border-2 transition-all hover:scale-105 text-left ${
                                                    (user?.ui_layout || 'modern') === 'modern'
                                                        ? 'border-proxmox-orange ring-2 ring-proxmox-orange/30'
                                                        : 'border-proxmox-border hover:border-gray-500'
                                                }`}
                                            >
                                                <div className="h-16 rounded-lg mb-2 relative overflow-hidden bg-proxmox-dark border border-proxmox-border">
                                                    {/* Modern preview: gradient sidebar, rounded cards */}
                                                    <div className="absolute left-0 top-0 bottom-0 w-5 bg-gradient-to-b from-proxmox-orange/30 to-purple-500/20" />
                                                    <div className="absolute right-1.5 top-1.5 left-7 h-2 rounded-full bg-proxmox-orange/40" />
                                                    <div className="absolute right-1.5 top-5 left-7 bottom-1.5 rounded-lg bg-proxmox-card border border-proxmox-border">
                                                        <div className="flex gap-1 p-1">
                                                            <div className="w-2 h-1.5 rounded-full bg-proxmox-orange/50" />
                                                            <div className="w-2 h-1.5 rounded-full bg-gray-600" />
                                                            <div className="w-2 h-1.5 rounded-full bg-gray-600" />
                                                        </div>
                                                    </div>
                                                    {(user?.ui_layout || 'modern') === 'modern' && (
                                                        <div className="absolute top-1 right-1 bg-proxmox-orange rounded-full p-0.5">
                                                            <Icons.Check className="w-3 h-3 text-white" />
                                                        </div>
                                                    )}
                                                </div>
                                                <div className="text-center">
                                                    <span className="text-xs font-medium">{t('layoutModern') || 'Modern'}</span>
                                                    <p className="text-[10px] text-gray-500 mt-0.5">{t('layoutModernDesc') || 'Cards, animations, gradients'}</p>
                                                </div>
                                            </button>
                                            {/* Corporate layout card */}
                                            <button
                                                onClick={async () => {
                                                    const result = await updatePreferences({ ui_layout: 'corporate' });
                                                    if (result.success) addToast(`${t('layoutStyle')}: ${t('layoutCorporate') || 'Corporate'}`, 'success');
                                                }}
                                                className={`p-3 rounded-xl border-2 transition-all hover:scale-105 text-left ${
                                                    user?.ui_layout === 'corporate'
                                                        ? 'border-proxmox-orange ring-2 ring-proxmox-orange/30'
                                                        : 'border-proxmox-border hover:border-gray-500'
                                                }`}
                                            >
                                                <div className="h-16 rounded mb-2 relative overflow-hidden bg-proxmox-dark border border-proxmox-border">
                                                    {/* Corporate preview: flat sidebar, tree lines, underline tabs */}
                                                    <div className="absolute left-0 top-0 bottom-0 w-5 bg-proxmox-card border-r border-proxmox-border">
                                                        <div className="mt-2 ml-1 space-y-1">
                                                            <div className="w-3 h-0.5 bg-gray-500" />
                                                            <div className="w-2.5 h-0.5 bg-gray-600 ml-1" />
                                                            <div className="w-2.5 h-0.5 bg-gray-600 ml-1" />
                                                        </div>
                                                    </div>
                                                    <div className="absolute right-1.5 top-1.5 left-7 h-2 bg-proxmox-card border-b border-proxmox-border flex items-end gap-1 px-1">
                                                        <div className="w-3 h-0.5 bg-proxmox-orange" />
                                                        <div className="w-3 h-0.5 bg-gray-600" />
                                                        <div className="w-3 h-0.5 bg-gray-600" />
                                                    </div>
                                                    <div className="absolute right-1.5 top-5 left-7 bottom-1.5 bg-proxmox-card border border-proxmox-border" />
                                                    {user?.ui_layout === 'corporate' && (
                                                        <div className="absolute top-1 right-1 bg-proxmox-orange rounded-full p-0.5">
                                                            <Icons.Check className="w-3 h-3 text-white" />
                                                        </div>
                                                    )}
                                                </div>
                                                <div className="text-center">
                                                    <span className="text-xs font-medium">{t('layoutCorporate') || 'Corporate'}</span>
                                                    <p className="text-[10px] text-gray-500 mt-0.5">{t('layoutCorporateDesc') || 'Enterprise style, dense'}</p>
                                                </div>
                                            </button>
                                        </div>
                                    </div>

                                    {/* NS: TaskBar Auto-Expand Setting - Feb 2026 */}
                                    <div className="pt-4 border-t border-proxmox-border">
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2 rounded-lg bg-blue-500/10">
                                                    <Icons.Layers className="w-5 h-5 text-blue-400" />
                                                </div>
                                                <div>
                                                    <p className="text-sm font-medium text-white">{t('taskbarAutoExpand') || 'TaskBar Auto-Expand'}</p>
                                                    <p className="text-xs text-gray-400">{t('taskbarAutoExpandDesc') || 'Automatically expand TaskBar when new tasks start'}</p>
                                                </div>
                                            </div>
                                            <button
                                                onClick={async () => {
                                                    // NS: Toggle current value - if true/undefined -> false, if false -> true
                                                    const currentValue = user?.taskbar_auto_expand !== false;
                                                    const newValue = !currentValue;
                                                    console.log('TaskBar auto-expand toggle:', currentValue, '->', newValue);
                                                    const result = await updatePreferences({ taskbar_auto_expand: newValue });
                                                    if (result.success) {
                                                        addToast(newValue ? (t('taskbarAutoExpandEnabled') || 'TaskBar auto-expand enabled') : (t('taskbarAutoExpandDisabled') || 'TaskBar auto-expand disabled'), 'success');
                                                    }
                                                }}
                                                className={`relative w-12 h-6 rounded-full transition-colors ${
                                                    user?.taskbar_auto_expand !== false ? 'bg-proxmox-orange' : 'bg-gray-600'
                                                }`}
                                            >
                                                <span className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${
                                                    user?.taskbar_auto_expand !== false ? 'left-7' : 'left-1'
                                                }`} />
                                            </button>
                                        </div>
                                    </div>
                                    
                                    <p className="text-xs text-gray-500 text-center">
                                        {t('themeNote') || 'Theme changes are applied immediately and saved to your account.'}
                                    </p>
                                </div>
                            )}
                            
                            {activeTab === 'security' && (
                                <div className="space-y-6">
                                    {/* Password Change */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                        <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                                            </svg>
                                            {t('resetPassword')}
                                        </h3>
                                        <form onSubmit={handleChangePassword} className="space-y-3">
                                            <input
                                                type="password"
                                                value={currentPassword}
                                                onChange={e => setCurrentPassword(e.target.value)}
                                                placeholder={t('currentPassword')}
                                                className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                required
                                            />
                                            <input
                                                type="password"
                                                value={newPassword}
                                                onChange={e => setNewPassword(e.target.value)}
                                                placeholder={t('newPassword')}
                                                className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                required
                                            />
                                            <p className="text-xs text-gray-500 -mt-1 mb-1">{getPasswordPolicyHint()}</p>
                                            <input
                                                type="password"
                                                value={confirmPassword}
                                                onChange={e => setConfirmPassword(e.target.value)}
                                                placeholder={t('confirmPassword')}
                                                className="w-full px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                required
                                            />
                                            <button
                                                type="submit"
                                                disabled={loading}
                                                className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium disabled:opacity-50"
                                            >
                                                {t('resetPassword')}
                                            </button>
                                        </form>
                                    </div>
                                    
                                    {/* 2FA Section */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                        <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                                            <Icons.Shield />
                                            {t('twoFactorAuth')}
                                        </h3>
                                        
                                        {!twoFAStatus.available ? (
                                            <p className="text-gray-400 text-sm">
                                                2FA nicht verfügbar. Server benötigt: pip install pyotp qrcode[pil]
                                            </p>
                                        ) : twoFAStatus.enabled ? (
                                            <div className="space-y-3">
                                                <div className="flex items-center gap-2 text-green-400">
                                                    <Icons.Check />
                                                    <span>{t('twoFactorEnabled')}</span>
                                                </div>
                                                <div className="flex gap-2">
                                                    <input
                                                        type="password"
                                                        value={disablePassword}
                                                        onChange={e => setDisablePassword(e.target.value)}
                                                        placeholder={t('currentPassword')}
                                                        className="flex-1 px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-sm"
                                                    />
                                                    <button
                                                        onClick={handleDisable2FA}
                                                        disabled={loading || !disablePassword}
                                                        className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm font-medium disabled:opacity-50"
                                                    >
                                                        {t('disable2FA')}
                                                    </button>
                                                </div>
                                            </div>
                                        ) : setupData ? (
                                            <div className="space-y-4">
                                                <p className="text-gray-400 text-sm">{t('scan2FACode')}</p>
                                                <div className="flex justify-center">
                                                    <img src={setupData.qr_code} alt="QR Code" className="rounded-lg" />
                                                </div>
                                                <div className="text-center">
                                                    <p className="text-xs text-gray-500 mb-1">{t('secretKey')}:</p>
                                                    <code className="text-xs text-proxmox-orange bg-proxmox-darker px-2 py-1 rounded">
                                                        {setupData.secret}
                                                    </code>
                                                </div>
                                                <div className="flex gap-2">
                                                    <input
                                                        type="text"
                                                        value={totpCode}
                                                        onChange={e => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                                        placeholder={t('enter2FACode')}
                                                        maxLength={6}
                                                        className="flex-1 px-3 py-2 bg-proxmox-darker border border-proxmox-border rounded-lg text-white text-center text-lg tracking-widest"
                                                    />
                                                    <button
                                                        onClick={handleVerify2FA}
                                                        disabled={loading || totpCode.length !== 6}
                                                        className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-sm font-medium disabled:opacity-50"
                                                    >
                                                        {t('verify2FA')}
                                                    </button>
                                                </div>
                                                <button
                                                    onClick={() => setSetupData(null)}
                                                    className="text-sm text-gray-400 hover:text-white"
                                                >
                                                    {t('cancel')}
                                                </button>
                                            </div>
                                        ) : (
                                            <button
                                                onClick={handleSetup2FA}
                                                disabled={loading}
                                                className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm font-medium disabled:opacity-50"
                                            >
                                                {t('setup2FA')}
                                            </button>
                                        )}
                                    </div>
                                </div>
                            )}
                            
                            {/* MK: Feb 2026 - API Tokens Tab */}
                            {activeTab === 'tokens' && (
                                <div className="space-y-4">
                                    {/* Created Token Banner - only shown once after creation */}
                                    {createdToken && (
                                        <div className="p-4 bg-yellow-500/10 border border-yellow-500/40 rounded-xl">
                                            <div className="flex items-start gap-2 mb-2">
                                                <Icons.AlertTriangle className="w-5 h-5 text-yellow-400 shrink-0 mt-0.5" />
                                                <p className="text-yellow-400 font-medium text-sm">Copy your token now - it won't be shown again!</p>
                                            </div>
                                            <div className="flex items-center gap-2 mt-2">
                                                <code className="flex-1 bg-proxmox-dark px-3 py-2 rounded text-sm text-green-400 font-mono break-all select-all border border-proxmox-border">{createdToken}</code>
                                                <button onClick={() => copyToken(createdToken)} className="px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded hover:bg-proxmox-hover text-sm shrink-0">
                                                    {tokenCopied ? <Icons.CheckCircle className="w-4 h-4 text-green-400" /> : <Icons.Copy className="w-4 h-4 text-gray-400" />}
                                                </button>
                                            </div>
                                            <button onClick={() => setCreatedToken(null)} className="text-xs text-gray-500 hover:text-gray-300 mt-2">Dismiss</button>
                                        </div>
                                    )}
                                    
                                    {/* Create New Token */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                        <h3 className="text-white font-medium mb-3 flex items-center gap-2">
                                            <Icons.Plus className="w-4 h-4 text-proxmox-orange" />
                                            Create API Token
                                        </h3>
                                        <div className="space-y-3">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Token Name</label>
                                                <input
                                                    type="text"
                                                    value={newTokenName}
                                                    onChange={e => setNewTokenName(e.target.value)}
                                                    placeholder="e.g. ci-pipeline, monitoring, backup-script"
                                                    maxLength={64}
                                                    className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm"
                                                />
                                            </div>
                                            <div className={`grid ${user?.role === 'admin' ? 'grid-cols-2' : 'grid-cols-1'} gap-3`}>
                                                {/* NS: Only admins can pick a different role - everyone else gets their own */}
                                                {user?.role === 'admin' && (
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Role</label>
                                                    <select
                                                        value={newTokenRole}
                                                        onChange={e => setNewTokenRole(e.target.value)}
                                                        className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm"
                                                    >
                                                        <option value="">Same as my role</option>
                                                        <option value="viewer">Viewer</option>
                                                        <option value="user">User</option>
                                                        <option value="admin">Admin</option>
                                                    </select>
                                                </div>
                                                )}
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Expires (optional)</label>
                                                    <select
                                                        value={newTokenExpiry}
                                                        onChange={e => setNewTokenExpiry(e.target.value)}
                                                        className="w-full px-3 py-2 bg-proxmox-secondary border border-proxmox-border rounded-lg text-white text-sm"
                                                    >
                                                        <option value="">Never</option>
                                                        <option value="7">7 days</option>
                                                        <option value="30">30 days</option>
                                                        <option value="90">90 days</option>
                                                        <option value="180">180 days</option>
                                                        <option value="365">1 year</option>
                                                    </select>
                                                </div>
                                            </div>
                                            <button
                                                onClick={createToken}
                                                disabled={loading || !newTokenName.trim()}
                                                className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 rounded-lg text-white text-sm flex items-center gap-2"
                                            >
                                                {loading ? <Icons.Loader className="w-4 h-4 animate-spin" /> : <Icons.Key className="w-4 h-4" />}
                                                Generate Token
                                            </button>
                                        </div>
                                    </div>
                                    
                                    {/* Existing Tokens */}
                                    <div className="bg-proxmox-dark border border-proxmox-border rounded-xl p-4">
                                        <h3 className="text-white font-medium mb-3 flex items-center gap-2">
                                            <Icons.Key className="w-4 h-4 text-blue-400" />
                                            Your Tokens
                                            <span className="text-xs text-gray-500 ml-auto">{tokens.filter(t => !t.revoked).length} active</span>
                                        </h3>
                                        {tokensLoading ? (
                                            <div className="text-center py-4"><Icons.Loader className="w-5 h-5 animate-spin text-gray-400 mx-auto" /></div>
                                        ) : tokens.length === 0 ? (
                                            <p className="text-gray-500 text-sm text-center py-4">No API tokens yet</p>
                                        ) : (
                                            <div className="space-y-2">
                                                {tokens.map(token => (
                                                    <div key={token.id} className={`flex items-center gap-3 p-3 rounded-lg border ${token.revoked ? 'border-red-500/20 bg-red-500/5 opacity-50' : 'border-proxmox-border bg-proxmox-secondary'}`}>
                                                        <div className="flex-1 min-w-0">
                                                            <div className="flex items-center gap-2 flex-wrap">
                                                                <span className="text-white text-sm font-medium">{token.name}</span>
                                                                <code className="text-xs text-gray-500 font-mono">pgx_{token.token_prefix}_...</code>
                                                                <span className={`text-xs px-1.5 py-0.5 rounded ${
                                                                    token.role === 'admin' ? 'bg-red-500/20 text-red-400' :
                                                                    token.role === 'user' ? 'bg-blue-500/20 text-blue-400' :
                                                                    'bg-gray-500/20 text-gray-400'
                                                                }`}>{token.role}</span>
                                                                {token.revoked ? <span className="text-xs text-red-400">revoked</span> : null}
                                                            </div>
                                                            <div className="text-xs text-gray-500 mt-1 flex gap-3 flex-wrap">
                                                                <span>Created: {new Date(token.created_at).toLocaleDateString()}</span>
                                                                {token.expires_at && <span className={new Date(token.expires_at) < new Date() ? 'text-red-400' : ''}>
                                                                    Expires: {new Date(token.expires_at).toLocaleDateString()}
                                                                </span>}
                                                                {token.last_used_at ? (
                                                                    <span>Last used: {new Date(token.last_used_at).toLocaleDateString()} from {token.last_used_ip}</span>
                                                                ) : <span className="text-gray-600">Never used</span>}
                                                            </div>
                                                        </div>
                                                        {!token.revoked && (
                                                            <button
                                                                onClick={() => { if (confirm(`Revoke token "${token.name}"? This cannot be undone.`)) revokeToken(token.id); }}
                                                                className="px-3 py-1.5 bg-red-500/10 text-red-400 rounded-lg text-xs hover:bg-red-500/20 border border-red-500/20 shrink-0"
                                                            >
                                                                Revoke
                                                            </button>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    
                                    {/* Usage Info */}
                                    <div className="bg-proxmox-dark/50 border border-proxmox-border rounded-xl p-4 text-sm text-gray-400 space-y-2">
                                        <h4 className="text-gray-300 font-medium flex items-center gap-2"><Icons.Info className="w-4 h-4" /> Usage</h4>
                                        <p>Use API tokens for scripts, CI/CD pipelines, and monitoring integrations:</p>
                                        <code className="block bg-proxmox-dark px-3 py-2 rounded text-xs font-mono text-green-400 border border-proxmox-border">
                                            curl -H "Authorization: Bearer pgx_..." {window.location.origin}/api/clusters
                                        </code>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            );
        }

