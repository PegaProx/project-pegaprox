        // ═══════════════════════════════════════════════
        // PegaProx - Datacenter
        // DatacenterTab (HA, multipath, corosync, bridges)
        // ═══════════════════════════════════════════════
        // Datacenter Tab Component (embedded in main view)

        // Datacenter Tab Component
        function DatacenterTab({ clusterId, addToast }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [activeSection, setActiveSection] = useState('summary');
            const [loading, setLoading] = useState(true);
            const [dcStatus, setDcStatus] = useState(null);
            const [clusterNodes, setClusterNodes] = useState([]);
            const [joinInfo, setJoinInfo] = useState(null);
            const [showJoinInfo, setShowJoinInfo] = useState(false);
            const [dcOptions, setDcOptions] = useState({});
            const [showEditOptions, setShowEditOptions] = useState(false);
            const [editingOptions, setEditingOptions] = useState({});
            const [storage, setStorage] = useState([]);
            const [showAddStorage, setShowAddStorage] = useState(false);
            
            // Multipath Easy Setup - NS Feb 2026
            const [multipathStatus, setMultipathStatus] = useState(null);
            const [multipathLoading, setMultipathLoading] = useState(false);
            const [showMultipathSetup, setShowMultipathSetup] = useState(false);
            const [multipathSetupData, setMultipathSetupData] = useState({ vendor: 'default', policy: 'service-time', skipExistingConfig: false });
            const [multipathSetupResult, setMultipathSetupResult] = useState(null);
            const [multipathSelectedNodes, setMultipathSelectedNodes] = useState(null);  // null = all nodes
            
            // Reset multipath state when cluster changes
            useEffect(() => {
                setMultipathStatus(null);
                setMultipathSetupResult(null);
                setMultipathSelectedNodes(null);
                setShowMultipathSetup(false);
            }, [clusterId]);
            const [newStorage, setNewStorage] = useState({ type: 'dir', storage: '', path: '', content: 'images,rootdir' });
            const [backupJobs, setBackupJobs] = useState([]);
            const [replicationJobs, setReplicationJobs] = useState([]);  // TODO: actually use this
            const [firewallOptions, setFirewallOptions] = useState({});
            const [firewallRules, setFirewallRules] = useState([]);
            const [showAddRuleModal, setShowAddRuleModal] = useState(false);
            const [newRule, setNewRule] = useState({ type: 'in', action: 'ACCEPT', enable: 1 });
            
            // MK: HA State Variables
            const [haManagerStatus, setHaManagerStatus] = useState([]);
            const [haResources, setHaResources] = useState([]);
            const [haGroups, setHaGroups] = useState([]);
            const [availableVmsForHa, setAvailableVmsForHa] = useState([]);
            const [showAddHaResource, setShowAddHaResource] = useState(false);
            const [showAddHaGroup, setShowAddHaGroup] = useState(false);
            const [showEditHaResource, setShowEditHaResource] = useState(null);
            const [showEditHaGroup, setShowEditHaGroup] = useState(null);
            const [newHaResource, setNewHaResource] = useState({ sid: '', state: 'started', group: '', max_restart: 1, max_relocate: 1, comment: '' });
            const [newHaGroup, setNewHaGroup] = useState({ group: '', nodes: '', restricted: 0, nofailback: 0 });
            
            const [showAddBackupJob, setShowAddBackupJob] = useState(false);
            // const [editBackupJob, setEditBackupJob] = useState(null);  // later
            const [newBackupJob, setNewBackupJob] = useState({
                enabled: 1,
                schedule: 'daily',
                storage: '',
                mode: 'snapshot',
                compress: 'zstd',
                vmid: '',
                node: '',
                mailnotification: 'always',
                mailto: ''
            });
            const [cpuInfo, setCpuInfo] = useState([]);
            const [recommendedCpu, setRecommendedCpu] = useState(null);
            const authHeaders = getAuthHeaders();
            
            // Node Management state
            const [showNodeJoinWizard, setShowNodeJoinWizard] = useState(false);
            const [showRemoveNodeModal, setShowRemoveNodeModal] = useState(false);
            const [nodeToRemove, setNodeToRemove] = useState(null);
            const [showMoveNodeModal, setShowMoveNodeModal] = useState(false);
            const [nodeToMove, setNodeToMove] = useState(null);
            
            // LW: SDN State - Feb 2026, GitHub Issue #38
            const [sdnData, setSdnData] = useState({ available: false, zones: [], vnets: [], subnets: [], controllers: [], ipams: [], dns: [], pending: false, debug: {} });
            const [sdnLoading, setSdnLoading] = useState(false);
            const [showAddZone, setShowAddZone] = useState(false);
            const [showAddVnet, setShowAddVnet] = useState(false);
            const [showAddSubnet, setShowAddSubnet] = useState(null); // vnet name when adding subnet
            const [showAddController, setShowAddController] = useState(false);
            const [showAddIpam, setShowAddIpam] = useState(false);
            const [showAddDns, setShowAddDns] = useState(false);
            const [showEditZone, setShowEditZone] = useState(null);
            const [newZone, setNewZone] = useState({ zone: '', type: 'simple', bridge: '', mtu: '', nodes: '', ipam: '', dns: '', dnszone: '', reversedns: '' });
            const [newVnet, setNewVnet] = useState({ vnet: '', zone: '', tag: '', alias: '' });
            const [newSubnet, setNewSubnet] = useState({ subnet: '', gateway: '', snat: 0, dhcp: 'none', 'dhcp-range': '' });
            const [newController, setNewController] = useState({ controller: '', type: 'evpn', asn: '', peers: '', 'bgp-multipath-as-path-relax': 0, ebgp: 0, 'ebgp-multihop': 0 });
            const [newIpam, setNewIpam] = useState({ ipam: '', type: 'pve', url: '', token: '', section: '' });
            const [newDns, setNewDns] = useState({ dns: '', type: 'powerdns', url: '', key: '', reversemaskv6: 64, ttl: 3600 });

            // Ceph state
            const [cephData, setCephData] = useState(null);
            const [cephLoading, setCephLoading] = useState(false);
            const [cephNode, setCephNode] = useState('');
            const [showCreatePool, setShowCreatePool] = useState(false);
            const [newPool, setNewPool] = useState({ name: '', size: 3, min_size: 2, pg_num: 128 });
            const [showCreateMon, setShowCreateMon] = useState(false);
            const [showCreateMds, setShowCreateMds] = useState(false);
            const [cephSubTab, setCephSubTab] = useState('status');

            /*
             * MK: CPU generation detection for recommended CPU type
             * Maps physical CPU model to x86-64 microarchitecture level
             * Used to suggest optimal QEMU cpu type in VM settings
             * 
             * Levels: v1 (baseline), v2-AES (most compatible), v3 (AVX2), v4 (AVX-512)
             * ChatGPT helped compile this list, I double-checked against Intel ARK
             */
            const detectCpuGeneration = (cpuModel) => {
                if (!cpuModel) return { level: 'v2-AES', generation: 'Unknown' };
                const model = cpuModel.toLowerCase();
                
                // Intel Xeon generations (server CPUs)
                if (model.includes('xeon')) {
                    // Xeon Scalable (Sapphire Rapids, Emerald Rapids)
                    if (model.includes('sapphire') || model.includes('emerald') || model.match(/[w\d]-[34]\d{3}/))
                        return { level: 'v4', generation: 'Intel Xeon Scalable 4th/5th Gen' };
                    // Xeon Scalable (Ice Lake, Cascade Lake)
                    if (model.includes('ice') || model.includes('cascade') || model.includes('platinum') || model.includes('gold') || model.includes('silver') || model.includes('bronze'))
                        return { level: 'v3', generation: 'Intel Xeon Scalable' };
                    // Xeon E5/E7 v4 (Broadwell)
                    if (model.includes('v4'))
                        return { level: 'v3', generation: 'Intel Xeon E5/E7 v4 (Broadwell)' };
                    // Xeon E5/E7 v3 (Haswell)
                    if (model.includes('v3'))
                        return { level: 'v3', generation: 'Intel Xeon E5/E7 v3 (Haswell)' };
                    // Xeon E5/E7 v2 (Ivy Bridge)
                    if (model.includes('v2'))
                        return { level: 'v2-AES', generation: 'Intel Xeon E5/E7 v2 (Ivy Bridge)' };
                    // Xeon E5/E7 v1 (Sandy Bridge)
                    if (model.includes('e5-') || model.includes('e7-'))
                        return { level: 'v2-AES', generation: 'Intel Xeon E5/E7 (Sandy Bridge)' };
                    // Older Xeons
                    return { level: 'v2-AES', generation: 'Intel Xeon (Legacy)' };
                }
                
                // Intel Core generations (desktop/laptop CPUs)
                if (model.includes('core')) {
                    if (model.includes('13th') || model.includes('14th') || model.includes('i9-13') || model.includes('i9-14') || model.includes('i7-13') || model.includes('i7-14'))
                        return { level: 'v4', generation: 'Intel Core 13th/14th Gen' };
                    if (model.includes('11th') || model.includes('12th') || model.includes('i9-12') || model.includes('i7-12') || model.includes('i9-11') || model.includes('i7-11'))
                        return { level: 'v3', generation: 'Intel Core 11th/12th Gen' };
                    if (model.includes('10th') || model.includes('i9-10') || model.includes('i7-10') || model.includes('i5-10'))
                        return { level: 'v3', generation: 'Intel Core 10th Gen' };
                    if (model.includes('8th') || model.includes('9th') || model.includes('i7-8') || model.includes('i7-9') || model.includes('i5-8') || model.includes('i5-9'))
                        return { level: 'v3', generation: 'Intel Core 8th/9th Gen' };
                    if (model.includes('6th') || model.includes('7th') || model.includes('i7-6') || model.includes('i7-7') || model.includes('i5-6') || model.includes('i5-7'))
                        return { level: 'v3', generation: 'Intel Core 6th/7th Gen (Skylake/Kaby Lake)' };
                    if (model.includes('4th') || model.includes('5th') || model.includes('i7-4') || model.includes('i7-5') || model.includes('i5-4') || model.includes('i5-5'))
                        return { level: 'v3', generation: 'Intel Core 4th/5th Gen (Haswell/Broadwell)' };
                    if (model.includes('3rd') || model.includes('2nd') || model.includes('i7-3') || model.includes('i7-2') || model.includes('i5-3') || model.includes('i5-2'))
                        return { level: 'v2-AES', generation: 'Intel Core 2nd/3rd Gen (Sandy/Ivy Bridge)' };
                    return { level: 'v2-AES', generation: 'Intel Core (Legacy)' };
                }
                
                // AMD EPYC generations (server CPUs)
                if (model.includes('epyc')) {
                    // EPYC 9xx4 series (Genoa, Zen 4)
                    if (model.match(/9\d{3}/) || model.includes('genoa'))
                        return { level: 'v4', generation: 'AMD EPYC Genoa (Zen 4)' };
                    // EPYC 7xx3 series (Milan, Zen 3)
                    if (model.match(/7\d{2}3/) || model.match(/77\d{2}/) || model.includes('milan'))
                        return { level: 'v3', generation: 'AMD EPYC Milan (Zen 3)' };
                    // EPYC 7xx2 series (Rome, Zen 2)
                    if (model.match(/7\d{2}2/) || model.includes('rome'))
                        return { level: 'v3', generation: 'AMD EPYC Rome (Zen 2)' };
                    // EPYC 7xx1 series (Naples, Zen 1)
                    if (model.match(/7\d{2}1/) || model.includes('naples'))
                        return { level: 'v2-AES', generation: 'AMD EPYC Naples (Zen 1)' };
                    return { level: 'v2-AES', generation: 'AMD EPYC' };
                }
                
                // AMD Ryzen/Threadripper generations
                if (model.includes('ryzen') || model.includes('threadripper')) {
                    if (model.includes('7000') || model.includes('9000') || model.match(/\d{1}-7\d{3}/) || model.match(/\d{1}-9\d{3}/))
                        return { level: 'v4', generation: 'AMD Ryzen 7000/9000 (Zen 4)' };
                    if (model.includes('5000') || model.includes('6000') || model.match(/\d{1}-5\d{3}/) || model.match(/\d{1}-6\d{3}/))
                        return { level: 'v3', generation: 'AMD Ryzen 5000/6000 (Zen 3)' };
                    if (model.includes('3000') || model.includes('4000') || model.match(/\d{1}-3\d{3}/) || model.match(/\d{1}-4\d{3}/))
                        return { level: 'v3', generation: 'AMD Ryzen 3000/4000 (Zen 2)' };
                    if (model.includes('1000') || model.includes('2000') || model.match(/\d{1}-1\d{3}/) || model.match(/\d{1}-2\d{3}/))
                        return { level: 'v2-AES', generation: 'AMD Ryzen 1000/2000 (Zen/Zen+)' };
                    return { level: 'v2-AES', generation: 'AMD Ryzen' };
                }
                
                // fallback for other/unknown CPUs
                if (model.includes('amd'))
                    return { level: 'v2-AES', generation: 'AMD (Unknown)' };
                if (model.includes('intel'))
                    return { level: 'v2-AES', generation: 'Intel (Unknown)' };
                
                return { level: 'v2-AES', generation: 'Unknown CPU' };
            };
            
            // Determine recommended CPU level based on all nodes
            const calculateRecommendedCpu = (cpuInfoList) => {
                if (!cpuInfoList || cpuInfoList.length === 0) return 'x86-64-v2-AES';
                
                const levels = cpuInfoList.map(c => c.detectedLevel);
                const levelOrder = ['v2-AES', 'v3', 'v4'];
                
                // Find the lowest common denominator
                let lowestIndex = levelOrder.length - 1;
                for (const level of levels) {
                    const idx = levelOrder.indexOf(level);
                    if (idx < lowestIndex && idx >= 0) lowestIndex = idx;
                }
                
                return `x86-64-${levelOrder[lowestIndex]}`;
            };
            
            // NS: authFetch wrapper with proper error handling
            // Returns null on network failure so callers need to check
            const authFetch = async function(url, options) {
                options = options || {};
                try {
                    const response = await fetch(url, {
                        ...options,
                        credentials: 'include',  // NS: Security - use cookies for auth
                        headers: Object.assign({}, options.headers, getAuthHeaders())
                    });
                    return response;
                } catch (err) {
                    console.error('Auth fetch error:', err);
                    return null;
                }
            };

            const sections = [
                { id: 'summary', labelKey: 'summary', icon: Icons.Activity },
                { id: 'cluster', labelKey: 'cluster', icon: Icons.Server },
                { id: 'options', labelKey: 'options', icon: Icons.Settings },
                { id: 'storage', labelKey: 'storage', icon: Icons.HardDrive },
                { id: 'sdn', labelKey: 'sdn', icon: Icons.Network },
                { id: 'backup', labelKey: 'backup', icon: Icons.Clock },
                { id: 'replication', labelKey: 'replication', icon: Icons.RefreshCw },
                { id: 'ha', labelKey: 'proxmoxNativeHa', icon: Icons.Activity },
                { id: 'cpucompat', labelKey: 'cpuCompatibility', icon: Icons.Cpu },
                { id: 'firewall', labelKey: 'firewall', icon: Icons.Shield },
                { id: 'ceph', labelKey: 'ceph', icon: Icons.Database },
            ];

            const storageTypes = [
                { id: 'dir', label: 'Directory', icon: '📁' },
                { id: 'lvm', label: 'LVM', icon: '💾' },
                { id: 'lvmthin', label: 'LVM-Thin', icon: '💾' },
                { id: 'btrfs', label: 'BTRFS', icon: '🌲' },
                { id: 'nfs', label: 'NFS', icon: '🌐' },
                { id: 'cifs', label: 'SMB/CIFS', icon: '🖥' },
                { id: 'iscsi', label: 'iSCSI', icon: '🔗' },
                { id: 'cephfs', label: 'CephFS', icon: '🐙' },
                { id: 'rbd', label: 'RBD', icon: '🐙' },
                { id: 'zfs', label: 'ZFS over iSCSI', icon: '⚡' },
                { id: 'zfspool', label: 'ZFS', icon: '⚡' },
                { id: 'pbs', label: 'Proxmox Backup Server', icon: '💼' },
                { id: 'esxi', label: 'ESXi', icon: '🖥' },
            ];

            const defaultOptions = {
                keyboard: 'de',
                http_proxy: '',
                console: '',
                email_from: '',
                mac_prefix: 'BC:24:11',
                max_workers: 4,
                // Migration (complex)
                migration_type: '',
                migration_network: '',
                // HA (complex)
                ha_shutdown_policy: '',
                // CRS (complex)
                crs_ha_rebalance: '',
                crs_mode: '',
                // Next ID Range (complex)
                next_id_lower: 100,
                next_id_upper: 999999999,
                // Bandwidth limits (complex)
                bwlimit_clone: '',
                bwlimit_migration: '',
                bwlimit_move: '',
                bwlimit_restore: '',
                bwlimit_default: '',
                // Tags
                user_tag_access: 'free',
                registered_tags: '',
                // Tag Style (complex)
                tag_style_shape: '',
                tag_style_color_map: '',
                tag_style_ordering: '',
            };
            
            // MK: Parse complex options from API response into editable fields
            const parseOptionsForEdit = (opts) => {
                const parsed = {...defaultOptions};
                
                // Simple fields
                if (opts.keyboard) parsed.keyboard = opts.keyboard;
                if (opts.http_proxy) parsed.http_proxy = opts.http_proxy;
                if (opts.console) parsed.console = opts.console;
                if (opts.email_from) parsed.email_from = opts.email_from;
                if (opts.mac_prefix) parsed.mac_prefix = opts.mac_prefix;
                if (opts.max_workers) parsed.max_workers = opts.max_workers;
                
                // Migration: can be string "type=secure,network=10.0.0.0/24" or object {type, network}
                if (opts.migration) {
                    if (typeof opts.migration === 'object') {
                        parsed.migration_type = opts.migration.type || '';
                        parsed.migration_network = opts.migration.network || '';
                    } else if (typeof opts.migration === 'string') {
                        opts.migration.split(',').forEach(part => {
                            const [k, v] = part.split('=');
                            if (k === 'type') parsed.migration_type = v;
                            if (k === 'network') parsed.migration_network = v;
                        });
                    }
                }
                
                // HA: can be object {shutdown_policy} or string
                if (opts.ha) {
                    if (typeof opts.ha === 'object') {
                        parsed.ha_shutdown_policy = opts.ha.shutdown_policy || '';
                    } else if (typeof opts.ha === 'string') {
                        opts.ha.split(',').forEach(part => {
                            const [k, v] = part.split('=');
                            if (k === 'shutdown_policy') parsed.ha_shutdown_policy = v;
                        });
                    }
                }
                
                // CRS: can be object {ha-rebalance-on-start, scheduling} or string
                if (opts.crs) {
                    if (typeof opts.crs === 'object') {
                        parsed.crs_ha_rebalance = opts.crs['ha-rebalance-on-start'] ? '1' : '';
                        parsed.crs_mode = opts.crs.scheduling || '';
                    } else if (typeof opts.crs === 'string') {
                        opts.crs.split(',').forEach(part => {
                            const [k, v] = part.split('=');
                            if (k === 'ha-rebalance-on-start') parsed.crs_ha_rebalance = v === '1' ? '1' : '';
                            if (k === 'scheduling') parsed.crs_mode = v;
                        });
                    }
                }
                
                // Next ID: can be object {lower, upper} or string
                const nextId = opts['next-id'] || opts.next_id;
                if (nextId) {
                    if (typeof nextId === 'object') {
                        parsed.next_id_lower = nextId.lower || 100;
                        parsed.next_id_upper = nextId.upper || 999999999;
                    } else if (typeof nextId === 'string') {
                        nextId.split(',').forEach(part => {
                            const [k, v] = part.split('=');
                            if (k === 'lower') parsed.next_id_lower = parseInt(v) || 100;
                            if (k === 'upper') parsed.next_id_upper = parseInt(v) || 999999999;
                        });
                    }
                }
                
                // Bandwidth limits: can be object or string
                if (opts.bwlimit) {
                    if (typeof opts.bwlimit === 'object') {
                        parsed.bwlimit_clone = opts.bwlimit.clone || '';
                        parsed.bwlimit_migration = opts.bwlimit.migration || '';
                        parsed.bwlimit_move = opts.bwlimit.move || '';
                        parsed.bwlimit_restore = opts.bwlimit.restore || '';
                        parsed.bwlimit_default = opts.bwlimit.default || '';
                    } else if (typeof opts.bwlimit === 'string') {
                        opts.bwlimit.split(',').forEach(part => {
                            const [k, v] = part.split('=');
                            if (k === 'clone') parsed.bwlimit_clone = v;
                            if (k === 'migration') parsed.bwlimit_migration = v;
                            if (k === 'move') parsed.bwlimit_move = v;
                            if (k === 'restore') parsed.bwlimit_restore = v;
                            if (k === 'default') parsed.bwlimit_default = v;
                        });
                    }
                }
                
                // Tag access - can be string "user-allow=free" or object
                const userTagAccess = opts['user-tag-access'] || opts.user_tag_access;
                if (userTagAccess) {
                    if (typeof userTagAccess === 'string' && userTagAccess.includes('=')) {
                        // Parse "user-allow=free" format
                        userTagAccess.split(',').forEach(part => {
                            const [k, v] = part.split('=');
                            if (k === 'user-allow') parsed.user_tag_access = v;
                        });
                    } else if (typeof userTagAccess === 'object' && userTagAccess['user-allow']) {
                        parsed.user_tag_access = userTagAccess['user-allow'];
                    } else {
                        parsed.user_tag_access = userTagAccess;
                    }
                }
                
                // Registered tags
                const regTags = opts['registered-tags'] || opts.registered_tags;
                if (regTags) parsed.registered_tags = regTags;
                
                // Tag style: can be object or string
                const tagStyle = opts['tag-style'] || opts.tag_style;
                if (tagStyle) {
                    if (typeof tagStyle === 'object') {
                        parsed.tag_style_shape = tagStyle.shape || '';
                        parsed.tag_style_color_map = tagStyle['color-map'] || '';
                        parsed.tag_style_ordering = tagStyle.ordering || '';
                    } else if (typeof tagStyle === 'string') {
                        tagStyle.split(',').forEach(part => {
                            const [k, v] = part.split('=');
                            if (k === 'shape') parsed.tag_style_shape = v;
                            if (k === 'color-map') parsed.tag_style_color_map = v;
                            if (k === 'ordering') parsed.tag_style_ordering = v;
                        });
                    }
                }
                
                return parsed;
            };
            
            // MK: Load datacenter options from API
            const loadOptions = async () => {
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/options`);
                    if (res?.ok) {
                        const opts = await res.json();
                        setDcOptions(opts);
                        setEditingOptions(parseOptionsForEdit(opts));
                    }
                } catch(e) {
                    console.error('Failed to load datacenter options:', e);
                }
            };

            useEffect(() => {
                fetchAllData();
            }, [clusterId]);

            useEffect(() => {
                if (activeSection === 'ceph') fetchCephData();
            }, [activeSection]);

            // NS: Dedicated function to refresh only storage list without full reload
            const refreshStorage = async () => {
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/storage`);
                    if (res?.ok) {
                        const storageData = await res.json();
                        console.log('Refreshed storage data:', storageData?.length || 0, 'items');
                        setStorage(storageData);
                    }
                } catch (e) {
                    console.error('Error refreshing storage:', e);
                }
            };

            const fetchAllData = async () => {
                setLoading(true);
                try {
                    // fetch everything in parallel
                    const results = await Promise.all([
                        authFetch(`${API_URL}/clusters/${clusterId}/datacenter/status`),
                        authFetch(`${API_URL}/clusters/${clusterId}/datacenter/cluster-info`),
                        authFetch(`${API_URL}/clusters/${clusterId}/datacenter/options`),
                        authFetch(`${API_URL}/clusters/${clusterId}/datacenter/storage`),
                        authFetch(`${API_URL}/clusters/${clusterId}/datacenter/backup`),
                        authFetch(`${API_URL}/clusters/${clusterId}/datacenter/replication`),
                        authFetch(`${API_URL}/clusters/${clusterId}/datacenter/firewall/options`),
                        authFetch(`${API_URL}/clusters/${clusterId}/datacenter/firewall/rules`),
                        authFetch(`${API_URL}/clusters/${clusterId}/datacenter/join-info`),
                        // MK: HA Data
                        authFetch(`${API_URL}/clusters/${clusterId}/datacenter/ha/status`),
                        authFetch(`${API_URL}/clusters/${clusterId}/proxmox-ha/resources`),
                        authFetch(`${API_URL}/clusters/${clusterId}/proxmox-ha/groups`),
                        // LW: SDN Data - Feb 2026
                        authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn`)
                    ]);
                    
                    const [r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13] = results;

                    if (r1?.ok) setDcStatus(await r1.json());
                    if (r2?.ok) {
                        const tmp = await r2.json();
                        
                        // Fetch summary for each node - NS Jan 2026
                        const nodesWithSummary = await Promise.all((tmp || []).map(async (node) => {
                            try {
                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${node.node || node.name}/summary`);
                                if (res?.ok) {
                                    const summary = await res.json();
                                    return { ...node, summary, name: node.node || node.name };
                                }
                            } catch(e) { console.error('Failed to load node summary:', e); }
                            return { ...node, summary: null, name: node.node || node.name };
                        }));
                        
                        setClusterNodes(nodesWithSummary);
                        
                        // Fetch CPU info for each online node
                        const online = (nodesWithSummary || []).filter(n => n.online !== 0);
                        const cpuPromises = online.map(async (node) => {
                            try {
                                // Use already fetched summary if available
                                if (node.summary) {
                                    const cpuModel = node.summary.cpuinfo?.model || 'Unknown';
                                    const detected = detectCpuGeneration(cpuModel);
                                    return {
                                        node: node.name,
                                        model: cpuModel,
                                        cores: node.summary.cpuinfo?.cores || 0,
                                        sockets: node.summary.cpuinfo?.sockets || 1,
                                        detectedLevel: detected.level,
                                        generation: detected.generation
                                    };
                                }
                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${node.name}/summary`);
                                if (res?.ok) {
                                    const s = await res.json();
                                    const cpuModel = s.cpuinfo?.model || 'Unknown';
                                    const detected = detectCpuGeneration(cpuModel);
                                    return {
                                        node: node.name,
                                        model: cpuModel,
                                        cores: s.cpuinfo?.cores || 0,
                                        sockets: s.cpuinfo?.sockets || 1,
                                        detectedLevel: detected.level,
                                        generation: detected.generation
                                    };
                                }
                            } catch(e) {}
                            return null;
                        });
                        
                        const cpuResults = (await Promise.all(cpuPromises)).filter(Boolean);
                        setCpuInfo(cpuResults);
                        setRecommendedCpu(calculateRecommendedCpu(cpuResults));
                    }
                    if (r3?.ok) {
                        const opts = await r3.json();
                        setDcOptions(opts);
                        setEditingOptions(parseOptionsForEdit(opts));
                    }
                    if (r4?.ok) {
                        const storageData = await r4.json();
                        console.log('Fetched storage data:', storageData?.length || 0, 'items');
                        setStorage(storageData);
                    }
                    if (r5?.ok) setBackupJobs(await r5.json());
                    if (r6?.ok) setReplicationJobs(await r6.json());
                    if (r7?.ok) setFirewallOptions(await r7.json());
                    if (r8?.ok) setFirewallRules(await r8.json());
                    if (r9?.ok) setJoinInfo(await r9.json());
                    // MK: HA Data
                    if (r10?.ok) setHaManagerStatus(await r10.json());
                    if (r11?.ok) setHaResources(await r11.json());
                    if (r12?.ok) setHaGroups(await r12.json());
                    // MK: SDN Data - Feb 2026
                    if (r13?.ok) {
                        const sdnResponse = await r13.json();
                        console.log('SDN API Response:', sdnResponse);
                        setSdnData(sdnResponse);
                    } else {
                        console.log('SDN API failed:', r13?.status, r13?.statusText);
                    }
                } catch(error) {
                    console.error('fetching datacenter data:', error);
                } finally {
                    setLoading(false);
                }
            };

            const fetchJoinInfo = async () => {
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/join-info`);
                    if (res && res.ok) {
                        const data = await res.json();
                        setJoinInfo(data);
                        setShowJoinInfo(true);
                    }
                } catch(e) { console.error(e); }
            };

            const fetchCephData = async () => {
                setCephLoading(true);
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/ceph`);
                    if (res?.ok) {
                        const d = await res.json();
                        setCephData(d);
                        if (d.node && !cephNode) setCephNode(d.node);
                    }
                } catch (e) {
                    console.error('Failed to load Ceph data:', e);
                }
                setCephLoading(false);
            };

            // NS: added PB for large storages, using toFixed(2) for more precision
            const formatBytes = (bytes) => {
                if (!bytes) return '0 B';
                const k = 1024;
                const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
            };

            const saveOptions = async () => {
                try {
                    const payload = {};
                    
                    // === Basic Settings ===
                    if (editingOptions.keyboard && editingOptions.keyboard !== '') {
                        payload.keyboard = editingOptions.keyboard;
                    }
                    
                    const validConsoleValues = ['vv', 'html5', 'xtermjs'];
                    if (editingOptions.console && validConsoleValues.includes(editingOptions.console)) {
                        payload.console = editingOptions.console;
                    }
                    
                    if (editingOptions.http_proxy && editingOptions.http_proxy.trim() !== '') {
                        payload.http_proxy = editingOptions.http_proxy;
                    }
                    
                    if (editingOptions.email_from && editingOptions.email_from.includes('@') && !editingOptions.email_from.includes('$')) {
                        payload.email_from = editingOptions.email_from;
                    }
                    
                    if (editingOptions.mac_prefix && /^[A-Fa-f0-9]{2}(:[A-Fa-f0-9]{2})*$/.test(editingOptions.mac_prefix)) {
                        payload.mac_prefix = editingOptions.mac_prefix.toUpperCase();
                    }
                    
                    if (editingOptions.max_workers && !isNaN(editingOptions.max_workers)) {
                        payload.max_workers = Math.max(1, Math.min(64, parseInt(editingOptions.max_workers)));
                    }
                    
                    // === Migration Settings ===
                    const migrationParts = [];
                    if (editingOptions.migration_type && editingOptions.migration_type !== '') {
                        migrationParts.push(`type=${editingOptions.migration_type}`);
                    }
                    if (editingOptions.migration_network && editingOptions.migration_network.trim() !== '') {
                        migrationParts.push(`network=${editingOptions.migration_network}`);
                    }
                    if (migrationParts.length > 0) {
                        payload.migration = migrationParts.join(',');
                    }
                    
                    // === HA Settings ===
                    if (editingOptions.ha_shutdown_policy && editingOptions.ha_shutdown_policy !== '') {
                        payload.ha = `shutdown_policy=${editingOptions.ha_shutdown_policy}`;
                    }
                    
                    // === CRS Settings ===
                    const crsParts = [];
                    if (editingOptions.crs_ha_rebalance === '1') {
                        crsParts.push('ha-rebalance-on-start=1');
                    }
                    if (editingOptions.crs_mode && editingOptions.crs_mode !== '') {
                        crsParts.push(`scheduling=${editingOptions.crs_mode}`);
                    }
                    if (crsParts.length > 0) {
                        payload.crs = crsParts.join(',');
                    }
                    
                    // === Next ID Range ===
                    const nextIdParts = [];
                    if (editingOptions.next_id_lower && !isNaN(editingOptions.next_id_lower)) {
                        nextIdParts.push(`lower=${editingOptions.next_id_lower}`);
                    }
                    if (editingOptions.next_id_upper && !isNaN(editingOptions.next_id_upper)) {
                        nextIdParts.push(`upper=${editingOptions.next_id_upper}`);
                    }
                    if (nextIdParts.length > 0) {
                        payload['next-id'] = nextIdParts.join(',');
                    }
                    
                    // === Bandwidth Limits ===
                    const bwParts = [];
                    if (editingOptions.bwlimit_clone && editingOptions.bwlimit_clone !== '' && editingOptions.bwlimit_clone !== '0') {
                        bwParts.push(`clone=${editingOptions.bwlimit_clone}`);
                    }
                    if (editingOptions.bwlimit_migration && editingOptions.bwlimit_migration !== '' && editingOptions.bwlimit_migration !== '0') {
                        bwParts.push(`migration=${editingOptions.bwlimit_migration}`);
                    }
                    if (editingOptions.bwlimit_move && editingOptions.bwlimit_move !== '' && editingOptions.bwlimit_move !== '0') {
                        bwParts.push(`move=${editingOptions.bwlimit_move}`);
                    }
                    if (editingOptions.bwlimit_restore && editingOptions.bwlimit_restore !== '' && editingOptions.bwlimit_restore !== '0') {
                        bwParts.push(`restore=${editingOptions.bwlimit_restore}`);
                    }
                    if (editingOptions.bwlimit_default && editingOptions.bwlimit_default !== '' && editingOptions.bwlimit_default !== '0') {
                        bwParts.push(`default=${editingOptions.bwlimit_default}`);
                    }
                    if (bwParts.length > 0) {
                        payload.bwlimit = bwParts.join(',');
                    }
                    
                    // === Tag Settings ===
                    // MK: user-tag-access is complex - Proxmox API is picky about format
                    // Skip for now - "free" is default anyway
                    // TODO: Implement proper format if needed
                    
                    // registered-tags is simpler - just semicolon-separated list
                    
                    if (editingOptions.registered_tags && editingOptions.registered_tags.trim() !== '') {
                        payload['registered-tags'] = editingOptions.registered_tags;
                    }
                    
                    // === Tag Style ===
                    const tagStyleParts = [];
                    if (editingOptions.tag_style_shape && editingOptions.tag_style_shape !== '') {
                        tagStyleParts.push(`shape=${editingOptions.tag_style_shape}`);
                    }
                    if (editingOptions.tag_style_color_map && editingOptions.tag_style_color_map !== '') {
                        tagStyleParts.push(`color-map=${editingOptions.tag_style_color_map}`);
                    }
                    if (editingOptions.tag_style_ordering && editingOptions.tag_style_ordering !== '') {
                        tagStyleParts.push(`ordering=${editingOptions.tag_style_ordering}`);
                    }
                    if (tagStyleParts.length > 0) {
                        payload['tag-style'] = tagStyleParts.join(',');
                    }
                    
                    console.log('Sending datacenter options:', payload);
                    
                    const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/options`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify(payload)
                    });
                    if (res.ok) {
                        // Refresh options from server to get latest state
                        await loadOptions();
                        setShowEditOptions(false);
                        addToast(t('optionsSaved') || 'Options saved', 'success');
                    } else {
                        const err = await res.json();
                        console.error('Datacenter options error:', err);
                        addToast(err.errors ? JSON.stringify(err.errors) : (err.error || 'Failed to save options'), 'error');
                    }
                } catch(e) { 
                    console.error(e); 
                    addToast('Failed to save options', 'error');
                }
            };

            const createStorage = async () => {
                // NS: Improved validation - Dec 2025
                // Validate required fields based on storage type
                const requiredFields = {
                    dir: ['path'],
                    nfs: ['server', 'export'],
                    cifs: ['server', 'share'],
                    lvm: ['vgname'],
                    lvmthin: ['vgname', 'thinpool'],
                    iscsi: ['portal', 'target'],
                    rbd: ['pool', 'monhost'],
                    cephfs: ['monhost'],
                    zfspool: ['pool'],
                    zfs: ['portal', 'target', 'pool'],
                    pbs: ['server', 'datastore', 'username', 'password'],
                    btrfs: ['path'],
                };
                
                const required = requiredFields[newStorage.type] || [];
                const missing = required.filter(f => !newStorage[f]);
                
                if (!newStorage.storage) {
                    addToast(t('storageIdRequired') || 'Storage ID is required', 'error');
                    return;
                }
                
                // Validate storage ID format
                if (!/^[a-zA-Z][a-zA-Z0-9\-\_\.]*$/.test(newStorage.storage)) {
                    addToast(t('invalidStorageId') || 'Storage ID must start with a letter and contain only letters, numbers, -, _, .', 'error');
                    return;
                }
                
                if (missing.length > 0) {
                    addToast(`${t('missingFields') || 'Missing required fields'}: ${missing.join(', ')}`, 'error');
                    return;
                }
                
                // NS: Additional validation for Shared LVM - need base (storage:lun) when baseStorage is set
                if (newStorage.type === 'lvm' && newStorage.baseStorage && !newStorage.base) {
                    addToast('Please select a LUN for Shared LVM', 'error');
                    return;
                }
                
                try {
                    // Build storage data based on type
                    const storageData = { ...newStorage };
                    
                    // Remove UI-only fields that shouldn't be sent to API
                    delete storageData.baseStorage; // LW: This is UI-only, 'base' contains the actual value
                    
                    // Remove empty fields
                    Object.keys(storageData).forEach(key => {
                        if (storageData[key] === '' || storageData[key] === undefined) {
                            delete storageData[key];
                        }
                    });
                    
                    // Convert enabled to disable (Proxmox uses disable=1 to disable)
                    if (storageData.enabled === false) {
                        storageData.disable = 1;
                    }
                    delete storageData.enabled;
                    
                    // NS: Debug output for troubleshooting
                    console.log('=== Storage Creation Debug ===');
                    console.log('Type:', storageData.type);
                    console.log('ID:', storageData.storage);
                    console.log('Base:', storageData.base);
                    console.log('VGName:', storageData.vgname);
                    console.log('Full data:', JSON.stringify(storageData, null, 2));
                    
                    const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/storage`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...authHeaders, 'Content-Type': 'application/json' },
                        body: JSON.stringify(storageData)
                    });
                    
                    const data = await res.json();
                    console.log('Create storage response:', res.status, data);
                    
                    if (res.ok && data.success) {
                        setShowAddStorage(false);
                        setNewStorage({ type: 'dir', storage: '', path: '', content: 'images,rootdir', enabled: true });
                        setScanResults([]); // Clear scan results
                        addToast(t('storageCreated') || 'Storage created successfully', 'success');
                        // NS: Only refresh storage list, not everything
                        await refreshStorage();
                    } else {
                        console.error('Storage creation failed:', data);
                        const errorMsg = data.error || data.message || 'Failed to create storage';
                        addToast(`Error: ${errorMsg}`, 'error');
                    }
                } catch(e) { 
                    console.error('Create storage error:', e);
                    addToast(`Error creating storage: ${e.message}`, 'error');
                }
            };
            
            // NS: Scan storage targets (iSCSI, NFS, CIFS, etc.)
            const [scanning, setScanning] = useState(false);
            const [scanResults, setScanResults] = useState([]);
            
            const scanStorage = async (type) => {
                setScanning(true);
                setScanResults([]);
                
                try {
                    const scanData = { type };
                    
                    // Add required params for each type
                    if (type === 'iscsi' && newStorage.portal) {
                        scanData.portal = newStorage.portal;
                    } else if (type === 'nfs' && newStorage.server) {
                        scanData.server = newStorage.server;
                    } else if (type === 'cifs' && newStorage.server) {
                        scanData.server = newStorage.server;
                        if (newStorage.username) scanData.username = newStorage.username;
                        if (newStorage.password) scanData.password = newStorage.password;
                        if (newStorage.domain) scanData.domain = newStorage.domain;
                    } else if (type === 'lvmthin' && newStorage.vgname) {
                        scanData.vgname = newStorage.vgname;
                    } else if (type === 'lvm') {
                        // No extra params needed
                    } else if (type === 'zfs') {
                        // No extra params needed
                    } else {
                        addToast(t('enterServerFirst') || 'Please enter server/portal address first', 'warning');
                        setScanning(false);
                        return;
                    }
                    
                    const res = await fetch(`${API_URL}/clusters/${clusterId}/storage/scan`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...authHeaders, 'Content-Type': 'application/json' },
                        body: JSON.stringify(scanData)
                    });
                    
                    const data = await res.json();
                    
                    if (res.ok && data.success) {
                        setScanResults(data.data || []);
                        if (data.data?.length === 0) {
                            addToast(t('noTargetsFound') || 'No targets found', 'warning');
                        }
                    } else {
                        addToast(`Scan failed: ${data.error}`, 'error');
                    }
                } catch (e) {
                    console.error('Scan error:', e);
                    addToast(`Scan error: ${e.message}`, 'error');
                } finally {
                    setScanning(false);
                }
            };

            const deleteStorage = async (storageId) => {
                if (!confirm(t('deleteStorageConfirm'))) return;
                try {
                    const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/storage/${storageId}`, { 
                        method: 'DELETE',
                        credentials: 'include',
                        headers: authHeaders
                    });
                    if (res.ok) {
                        setStorage(storage.filter(s => s.storage !== storageId));
                    }else{
                        const data = await res.json();
                        alert(`Error: ${data.error || 'Failed to delete storage'}`);
                    }
                } catch(e) { 
                    console.error('Delete storage error:', e);
                    // dont show alert here, too annoying
                }
            };

            // NS: backup job stuff below
            const deleteBackupJob = async (jobId) => {
                if (!confirm(t('deleteBackupJobConfirm'))) return;
                try {
                    const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/backup/${jobId}`, { 
                        method: 'DELETE',
                        credentials: 'include',
                        headers: authHeaders
                    });
                    if (res.ok) setBackupJobs(backupJobs.filter(j => j.id !== jobId));
                } catch(e) { /* ignore */ }
            };

            const createBackupJob = async () => {
                try {
                    const jobData = { ...newBackupJob };
                    // Convert schedule to Proxmox systemd calender format
                    // Proxmox uses systemd calender events, not cron!
                    const scheduleMap = {
                        'daily': '02:00',           // Daily at 2 AM
                        'weekly': 'sun 02:00',      // Sunday at 2 AM
                        'monthly': '*-*-01 02:00',  // First of month at 2 AM
                        'hourly': '*:00'            // Every hour
                    };
                    if(scheduleMap[jobData.schedule]) {
                        jobData.schedule = scheduleMap[jobData.schedule];
                    }
                    
                    // handle vmid: if empty or 'all', set all=1 flag
                    if(!jobData.vmid || jobData.vmid === '' || jobData.vmid === 'all') {
                        jobData.all = 1;
                        delete jobData.vmid;
                    }
                    
                    // Remove empty fileds (but not 'all')
                    Object.keys(jobData).forEach(key => {
                        if(key !== 'all' && (jobData[key] === '' || jobData[key] === null)) {
                            delete jobData[key];
                        }
                    });
                    
                    const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/backup`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { ...authHeaders, 'Content-Type': 'application/json' },
                        body: JSON.stringify(jobData)
                    });
                    
                    if(res.ok) {
                        setShowAddBackupJob(false);
                        setNewBackupJob({
                            enabled: 1, schedule: 'daily', storage: '', mode: 'snapshot',
                            compress: 'zstd', vmid: '', node: '', mailnotification: 'always', mailto: ''
                        });
                        // Reload backup jobs
                        const backupRes = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/backup`);
                        if(backupRes && backupRes.ok) setBackupJobs(await backupRes.json());
                    }else{
                        const err = await res.json();
                        alert(err.error || 'Failed');
                    }
                } catch(e) {
                    console.error(e);
                }
            };

            const deleteFirewallRule = async (pos) => {
                if(!confirm(t('deleteRuleConfirm'))) return;
                try {
                    const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/firewall/rules/${pos}`, { 
                        method: 'DELETE',
                        credentials: 'include',
                        headers: authHeaders
                    });
                    if (res.ok) setFirewallRules(firewallRules.filter(r => r.pos !== pos));
                } catch(e) { console.error(e); }
            };

            if (loading) {
                return (
                    <div className="flex items-center justify-center h-64">
                        <Icons.RotateCw />
                        <span className="ml-2">{t('loadingDatacenter') || 'Loading datacenter data / Lade Datacenter Daten...'}</span>
                    </div>
                );
            }

            return (
                <div className="flex gap-6">
                    {/* Sidebar */}
                    <div className="w-48 flex-shrink-0">
                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-3 sticky top-6">
                            <nav className="space-y-1">
                                {sections.map(section => (
                                    <button
                                        key={section.id}
                                        onClick={() => setActiveSection(section.id)}
                                        className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${
                                            activeSection === section.id
                                                ? 'bg-proxmox-orange text-white'
                                                : 'text-gray-400 hover:bg-proxmox-dark hover:text-white'
                                        }`}
                                    >
                                        <section.icon />
                                        {t(section.labelKey)}
                                    </button>
                                ))}
                            </nav>
                        </div>
                    </div>

                    {/* Content */}
                    <div className="flex-1 space-y-6">
                        {/* Summary */}
                        {activeSection === 'summary' && dcStatus && (
                            <>
                                <div className="grid grid-cols-2 gap-6">
                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                        <h3 className="text-lg font-semibold mb-4 text-green-400">Status</h3>
                                        <div className="flex items-center justify-center">
                                            <div className={`w-20 h-20 rounded-full flex items-center justify-center text-3xl ${dcStatus.cluster?.quorate ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                                                {dcStatus.cluster?.quorate ? '✓' : '✗'}
                                            </div>
                                        </div>
                                        <p className="text-center mt-4 text-sm text-gray-400">
                                            {dcStatus.cluster?.name} | Quorate: {dcStatus.cluster?.quorate ? 'Yes' : 'No'}
                                        </p>
                                    </div>
                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                        <h3 className="text-lg font-semibold mb-4">Nodes</h3>
                                        <div className="space-y-3">
                                            <div className="flex justify-between"><span className="text-green-400">● Online</span><span className="font-bold text-xl">{dcStatus.nodes?.online || 0}</span></div>
                                            <div className="flex justify-between"><span className="text-red-400">✗ Offline</span><span className="font-bold text-xl">{dcStatus.nodes?.offline || 0}</span></div>
                                        </div>
                                    </div>
                                </div>

                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                    <h3 className="text-lg font-semibold mb-4 text-cyan-400">Guests</h3>
                                    <div className="grid grid-cols-2 gap-6">
                                        <div>
                                            <h4 className="font-medium mb-3">Virtual Machines</h4>
                                            <div className="space-y-2 text-sm">
                                                <div className="flex justify-between"><span className="text-green-400">● Running</span><span>{dcStatus.guests?.vms?.running || 0}</span></div>
                                                <div className="flex justify-between"><span className="text-gray-400">â—‹ Stopped</span><span>{dcStatus.guests?.vms?.stopped || 0}</span></div>
                                            </div>
                                        </div>
                                        <div>
                                            <h4 className="font-medium mb-3">LXC Container</h4>
                                            <div className="space-y-2 text-sm">
                                                <div className="flex justify-between"><span className="text-green-400">● Running</span><span>{dcStatus.guests?.containers?.running || 0}</span></div>
                                                <div className="flex justify-between"><span className="text-gray-400">â—‹ Stopped</span><span>{dcStatus.guests?.containers?.stopped || 0}</span></div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                    <h3 className="text-lg font-semibold mb-4 text-yellow-400">Resources</h3>
                                    <div className="grid grid-cols-3 gap-6">
                                        {['cpu', 'memory', 'storage'].map(type => (
                                            <div key={type} className="text-center">
                                                <h4 className="font-medium mb-3 capitalize">{type}</h4>
                                                <div className="text-3xl font-bold text-blue-400">{dcStatus.resources?.[type]?.percent || 0}%</div>
                                                <p className="text-xs text-gray-500 mt-2">
                                                    {type === 'cpu' ? `${dcStatus.resources?.cpu?.total || 0} CPU(s)` : formatBytes(dcStatus.resources?.[type]?.total)}
                                                </p>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </>
                        )}

                        {/* Cluster Nodes */}
                        {activeSection === 'cluster' && (
                            <div className="space-y-4">
                                {/* Cluster Information Card */}
                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                    <div className="p-4 border-b border-proxmox-border">
                                        <h3 className="font-semibold flex items-center gap-2">
                                            <Icons.Info />
                                            Cluster Information
                                        </h3>
                                    </div>
                                    <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-xs text-gray-500 mb-1">Cluster Name</label>
                                            <div className="flex items-center gap-2">
                                                <input 
                                                    readOnly 
                                                    value={joinInfo?.cluster_name || dcStatus?.cluster?.name || 'Loading...'} 
                                                    className="flex-1 bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 font-mono text-sm"
                                                />
                                                <button 
                                                    onClick={() => navigator.clipboard.writeText(joinInfo?.cluster_name || dcStatus?.cluster?.name || '')}
                                                    className="p-2 bg-proxmox-dark hover:bg-proxmox-border rounded transition-colors"
                                                    title="Copy"
                                                >
                                                    <Icons.Copy />
                                                </button>
                                            </div>
                                        </div>
                                        <div>
                                            <label className="block text-xs text-gray-500 mb-1">Cluster IP / Join Address</label>
                                            <div className="flex items-center gap-2">
                                                <input 
                                                    readOnly 
                                                    value={joinInfo?.preferred_node || clusterNodes[0]?.ring0_addr || clusterNodes[0]?.ip || 'Loading...'} 
                                                    className="flex-1 bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 font-mono text-sm"
                                                />
                                                <button 
                                                    onClick={() => navigator.clipboard.writeText(joinInfo?.preferred_node || clusterNodes[0]?.ring0_addr || '')}
                                                    className="p-2 bg-proxmox-dark hover:bg-proxmox-border rounded transition-colors"
                                                    title="Copy"
                                                >
                                                    <Icons.Copy />
                                                </button>
                                            </div>
                                        </div>
                                        <div className="md:col-span-2">
                                            <label className="block text-xs text-gray-500 mb-1">Fingerprint</label>
                                            <div className="flex items-center gap-2">
                                                <textarea 
                                                    readOnly 
                                                    value={joinInfo?.fingerprint || 'Loading... (If empty, run "pvecm status" on a node)'} 
                                                    className="flex-1 bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 font-mono text-xs h-16 resize-none"
                                                />
                                                <button 
                                                    onClick={() => navigator.clipboard.writeText(joinInfo?.fingerprint || '')}
                                                    className="p-2 bg-proxmox-dark hover:bg-proxmox-border rounded transition-colors self-start"
                                                    title="Copy"
                                                >
                                                    <Icons.Copy />
                                                </button>
                                            </div>
                                        </div>
                                        {joinInfo?.nodelist && joinInfo.nodelist.length > 0 && (
                                            <div className="md:col-span-2">
                                                <label className="block text-xs text-gray-500 mb-1">Available Join Nodes</label>
                                                <div className="flex flex-wrap gap-2">
                                                    {joinInfo.nodelist.map((node, idx) => (
                                                        <div key={idx} className="px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm font-mono">
                                                            {node.name}: {node.ring0_addr || node.pve_addr}
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                    <div className="px-4 pb-4">
                                        <p className="text-xs text-gray-500">
                                            {t('nodeJoinHint') || 'To add a new node, run on the new node:'} <code className="bg-proxmox-dark px-1 rounded">pvecm add {joinInfo?.preferred_node || clusterNodes[0]?.ring0_addr || 'IP'}</code>
                                        </p>
                                    </div>
                                </div>

                                {/* Cluster Nodes Table */}
                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                    <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                        <h3 className="font-semibold">Cluster Nodes</h3>
                                        <div className="flex items-center gap-3">
                                            <span className="text-sm text-gray-400">{(clusterNodes || []).length} Node(s)</span>
                                            <button onClick={() => setShowNodeJoinWizard(true)} className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white"><Icons.Plus className="w-4 h-4" />Add Node</button>
                                        </div>
                                    </div>
                                    <table className="w-full">
                                        <thead className="bg-proxmox-dark">
                                            <tr>
                                                <th className="text-left p-3 text-sm text-gray-400">Nodename</th>
                                                <th className="text-left p-3 text-sm text-gray-400">ID</th>
                                                <th className="text-left p-3 text-sm text-gray-400">Votes</th>
                                                <th className="text-left p-3 text-sm text-gray-400">Ring 0 Address</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {(clusterNodes || []).map((node, idx) => (
                                                <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                    <td className="p-3 font-medium">{node.name}</td>
                                                    <td className="p-3">{node.nodeid}</td>
                                                    <td className="p-3">{node.quorum_votes || 1}</td>
                                                    <td className="p-3 font-mono text-sm">{node.ring0_addr || node.ip || '-'}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}
                        
                        
                        {/* Options */}
                        {activeSection === 'options' && (
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                    <h3 className="font-semibold">Datacenter Options</h3>
                                    <button onClick={() => {
                                        if (!showEditOptions) {
                                            // MK: Parse complex options when opening edit form
                                            setEditingOptions(parseOptionsForEdit(dcOptions));
                                        }
                                        setShowEditOptions(!showEditOptions);
                                    }} className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark hover:bg-proxmox-border rounded-lg text-sm">
                                        <Icons.Edit /> Edit
                                    </button>
                                </div>
                                {showEditOptions ? (
                                    <div className="p-4 space-y-4">
                                        <div className="grid grid-cols-2 gap-4">
                                            {/* Basic Settings */}
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Keyboard Layout</label>
                                                <select value={editingOptions.keyboard || 'de'} onChange={e => setEditingOptions({...editingOptions, keyboard: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                    <option value="de">German (de)</option>
                                                    <option value="de-ch">German (Swiss)</option>
                                                    <option value="en-us">English (US)</option>
                                                    <option value="en-gb">English (GB)</option>
                                                    <option value="fr">French</option>
                                                    <option value="fr-ch">French (Swiss)</option>
                                                    <option value="es">Spanish</option>
                                                    <option value="it">Italian</option>
                                                    <option value="nl">Dutch</option>
                                                    <option value="pl">Polish</option>
                                                    <option value="pt">Portuguese</option>
                                                    <option value="pt-br">Portuguese (Brazil)</option>
                                                    <option value="ru">Russian</option>
                                                    <option value="ja">Japanese</option>
                                                    <option value="sv">Swedish</option>
                                                    <option value="no">Norwegian</option>
                                                    <option value="da">Danish</option>
                                                    <option value="fi">Finnish</option>
                                                    <option value="tr">Turkish</option>
                                                </select>
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Console Viewer</label>
                                                <select value={editingOptions.console || ''} onChange={e => setEditingOptions({...editingOptions, console: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                    <option value="">Default (xterm.js)</option>
                                                    <option value="xtermjs">xterm.js</option>
                                                    <option value="html5">noVNC</option>
                                                    <option value="vv">SPICE (virt-viewer)</option>
                                                </select>
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">HTTP Proxy</label>
                                                <input value={editingOptions.http_proxy || ''} onChange={e => setEditingOptions({...editingOptions, http_proxy: e.target.value})} placeholder="http://proxy:port" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Email from address</label>
                                                <input value={editingOptions.email_from || ''} onChange={e => setEditingOptions({...editingOptions, email_from: e.target.value})} placeholder="root@$hostname" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">MAC address prefix</label>
                                                <input value={editingOptions.mac_prefix || ''} onChange={e => setEditingOptions({...editingOptions, mac_prefix: e.target.value})} placeholder="BC:24:11" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Max Workers/bulk-action</label>
                                                <input type="number" min="1" max="64" value={editingOptions.max_workers || 4} onChange={e => setEditingOptions({...editingOptions, max_workers: parseInt(e.target.value) || 4})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                            </div>
                                        </div>
                                        
                                        {/* Migration Settings */}
                                        <div className="border-t border-proxmox-border pt-4">
                                            <h4 className="text-sm font-medium text-gray-300 mb-3">Migration Settings</h4>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Migration Type</label>
                                                    <select value={editingOptions.migration_type || ''} onChange={e => setEditingOptions({...editingOptions, migration_type: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                        <option value="">Default (secure)</option>
                                                        <option value="secure">Secure (encrypted)</option>
                                                        <option value="insecure">Insecure (faster)</option>
                                                    </select>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Migration Network</label>
                                                    <input value={editingOptions.migration_network || ''} onChange={e => setEditingOptions({...editingOptions, migration_network: e.target.value})} placeholder="e.g. 10.0.0.0/24" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                    <span className="text-xs text-gray-500">CIDR network for migration traffic</span>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        {/* HA Settings */}
                                        <div className="border-t border-proxmox-border pt-4">
                                            <h4 className="text-sm font-medium text-gray-300 mb-3">HA Settings</h4>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Shutdown Policy</label>
                                                    <select value={editingOptions.ha_shutdown_policy || ''} onChange={e => setEditingOptions({...editingOptions, ha_shutdown_policy: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                        <option value="">Default (conditional)</option>
                                                        <option value="freeze">Freeze - keep resources frozen on shutdown</option>
                                                        <option value="failover">Failover - migrate to other node</option>
                                                        <option value="migrate">Migrate - always migrate</option>
                                                        <option value="conditional">Conditional - migrate if possible</option>
                                                    </select>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        {/* Cluster Resource Scheduling */}
                                        <div className="border-t border-proxmox-border pt-4">
                                            <h4 className="text-sm font-medium text-gray-300 mb-3">Cluster Resource Scheduling (CRS)</h4>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">HA Rebalance on Start</label>
                                                    <select value={editingOptions.crs_ha_rebalance || ''} onChange={e => setEditingOptions({...editingOptions, crs_ha_rebalance: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                        <option value="">Disabled</option>
                                                        <option value="1">Enabled - auto-rebalance HA resources on node start</option>
                                                    </select>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">CRS Scheduling Mode</label>
                                                    <select value={editingOptions.crs_mode || ''} onChange={e => setEditingOptions({...editingOptions, crs_mode: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                        <option value="">Default (basic)</option>
                                                        <option value="basic">Basic - simple load distribution</option>
                                                        <option value="static">Static - consider static resource config</option>
                                                    </select>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        {/* VMID Range */}
                                        <div className="border-t border-proxmox-border pt-4">
                                            <h4 className="text-sm font-medium text-gray-300 mb-3">Next Free VMID Range</h4>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Lower Bound</label>
                                                    <input type="number" min="100" max="999999999" value={editingOptions.next_id_lower || 100} onChange={e => setEditingOptions({...editingOptions, next_id_lower: parseInt(e.target.value) || 100})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Upper Bound</label>
                                                    <input type="number" min="100" max="999999999" value={editingOptions.next_id_upper || 999999999} onChange={e => setEditingOptions({...editingOptions, next_id_upper: parseInt(e.target.value) || 999999999})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                </div>
                                            </div>
                                        </div>
                                        
                                        {/* Bandwidth Limits */}
                                        <div className="border-t border-proxmox-border pt-4">
                                            <h4 className="text-sm font-medium text-gray-300 mb-3">Bandwidth Limits (MiB/s, 0 = unlimited)</h4>
                                            <div className="grid grid-cols-3 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Clone</label>
                                                    <input type="number" min="0" value={editingOptions.bwlimit_clone || ''} onChange={e => setEditingOptions({...editingOptions, bwlimit_clone: e.target.value})} placeholder="0" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Migration</label>
                                                    <input type="number" min="0" value={editingOptions.bwlimit_migration || ''} onChange={e => setEditingOptions({...editingOptions, bwlimit_migration: e.target.value})} placeholder="0" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Move</label>
                                                    <input type="number" min="0" value={editingOptions.bwlimit_move || ''} onChange={e => setEditingOptions({...editingOptions, bwlimit_move: e.target.value})} placeholder="0" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Restore</label>
                                                    <input type="number" min="0" value={editingOptions.bwlimit_restore || ''} onChange={e => setEditingOptions({...editingOptions, bwlimit_restore: e.target.value})} placeholder="0" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Default</label>
                                                    <input type="number" min="0" value={editingOptions.bwlimit_default || ''} onChange={e => setEditingOptions({...editingOptions, bwlimit_default: e.target.value})} placeholder="0" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                </div>
                                            </div>
                                        </div>
                                        
                                        {/* Tags */}
                                        <div className="border-t border-proxmox-border pt-4">
                                            <h4 className="text-sm font-medium text-gray-300 mb-3">Tag Settings</h4>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">User Tag Access</label>
                                                    <select value={editingOptions.user_tag_access || 'free'} disabled className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm opacity-50 cursor-not-allowed">
                                                        <option value="free">Free - users can create any tags</option>
                                                        <option value="existing">Existing - only use existing tags</option>
                                                        <option value="list">List - only use registered tags</option>
                                                        <option value="none">None - no tag editing allowed</option>
                                                    </select>
                                                    <span className="text-xs text-gray-500">Edit via Proxmox UI</span>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Registered Tags</label>
                                                    <input value={editingOptions.registered_tags || ''} onChange={e => setEditingOptions({...editingOptions, registered_tags: e.target.value})} placeholder="tag1;tag2;tag3" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                    <span className="text-xs text-gray-500">Semicolon-separated list of allowed tags</span>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        {/* Tag Style */}
                                        <div className="border-t border-proxmox-border pt-4">
                                            <h4 className="text-sm font-medium text-gray-300 mb-3">Tag Style Override</h4>
                                            <div className="grid grid-cols-3 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Shape</label>
                                                    <select value={editingOptions.tag_style_shape || ''} onChange={e => setEditingOptions({...editingOptions, tag_style_shape: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                        <option value="">Default</option>
                                                        <option value="full">Full</option>
                                                        <option value="circle">Circle</option>
                                                        <option value="dense">Dense</option>
                                                        <option value="none">None</option>
                                                    </select>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Color Mode</label>
                                                    <select value={editingOptions.tag_style_color_map || ''} onChange={e => setEditingOptions({...editingOptions, tag_style_color_map: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                        <option value="">Default</option>
                                                        <option value="auto">Auto - generate from tag name</option>
                                                    </select>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Ordering</label>
                                                    <select value={editingOptions.tag_style_ordering || ''} onChange={e => setEditingOptions({...editingOptions, tag_style_ordering: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                        <option value="">Default (config)</option>
                                                        <option value="config">Config order</option>
                                                        <option value="alphabetical">Alphabetical</option>
                                                    </select>
                                                </div>
                                            </div>
                                        </div>
                                        
                                        <div className="flex gap-2 pt-4 border-t border-proxmox-border">
                                            <button onClick={saveOptions} className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm">{t('save')}</button>
                                            <button onClick={() => setShowEditOptions(false)} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-border rounded-lg text-sm">{t('cancel')}</button>
                                        </div>
                                    </div>
                                ) : (
                                    <table className="w-full">
                                        <tbody>
                                            {(() => {
                                                // MK: Helper to safely format values - API sometimes returns objects
                                                const formatVal = (val, fallback = 'Default') => {
                                                    if (val === null || val === undefined || val === '') return fallback;
                                                    if (typeof val === 'object') {
                                                        // Convert object to readable string
                                                        return Object.entries(val).map(([k,v]) => `${k}: ${v}`).join(', ') || fallback;
                                                    }
                                                    return String(val);
                                                };
                                                return [
                                                    ['Keyboard Layout', formatVal(dcOptions.keyboard, 'German (de)')],
                                                    ['HTTP proxy', formatVal(dcOptions.http_proxy, 'none')],
                                                    ['Console Viewer', formatVal(dcOptions.console, 'Default (xterm.js)')],
                                                    ['Email from address', formatVal(dcOptions.email_from, 'root@$hostname')],
                                                    ['MAC address prefix', formatVal(dcOptions.mac_prefix, 'BC:24:11')],
                                                    ['Migration Settings', formatVal(dcOptions.migration, 'Default')],
                                                    ['HA Settings', formatVal(dcOptions.ha, 'Default')],
                                                    ['Cluster Resource Scheduling', formatVal(dcOptions.crs, 'Default')],
                                                    ['U2F Settings', formatVal(dcOptions.u2f, 'None')],
                                                    ['WebAuthn Settings', formatVal(dcOptions.webauthn, 'None')],
                                                    ['Bandwidth Limits', formatVal(dcOptions.bwlimit, 'None')],
                                                    ['Maximal Workers/bulk-action', formatVal(dcOptions.max_workers, '4')],
                                                    ['Next Free VMID Range', formatVal(dcOptions['next-id'], 'Default')],
                                                    ['Tag Style Override', formatVal(dcOptions['tag-style'], 'No Overrides')],
                                                    ['User Tag Access', formatVal(dcOptions['user-tag-access'], 'Mode: free')],
                                                    ['Registered Tags', formatVal(dcOptions['registered-tags'], 'No Registered Tags')],
                                                ].map(([key, value], idx) => (
                                                    <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/30">
                                                        <td className="p-3 text-gray-400 w-1/3">{key}</td>
                                                        <td className="p-3">{value}</td>
                                                    </tr>
                                                ));
                                            })()}
                                        </tbody>
                                    </table>
                                )}
                            </div>
                        )}

                        {/* Storage */}
                        {activeSection === 'storage' && (
                            <div className="space-y-4">
                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                    <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                        <h3 className="font-semibold flex items-center gap-2">
                                            <Icons.HardDrive />
                                            Storage Configuration
                                        </h3>
                                        <div className="flex gap-2">
                                            <button 
                                                onClick={refreshStorage} 
                                                className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark hover:bg-proxmox-hover border border-proxmox-border rounded-lg text-sm transition-colors"
                                                title="Refresh storage list"
                                            >
                                                <Icons.RefreshCw />
                                            </button>
                                            <button onClick={() => setShowAddStorage(true)} className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white transition-colors">
                                                <Icons.Plus /> {t('add')}
                                            </button>
                                        </div>
                                    </div>
                                    <div className="overflow-x-auto">
                                        <table className="w-full">
                                            <thead className="bg-proxmox-dark">
                                                <tr>
                                                    <th className="text-left p-3 text-sm text-gray-400">ID</th>
                                                    <th className="text-left p-3 text-sm text-gray-400">{t('type')}</th>
                                                    <th className="text-left p-3 text-sm text-gray-400">Content</th>
                                                    <th className="text-left p-3 text-sm text-gray-400">Path/Server</th>
                                                    <th className="text-left p-3 text-sm text-gray-400">{t('nodes')}</th>
                                                    <th className="text-left p-3 text-sm text-gray-400">Shared</th>
                                                    <th className="text-left p-3 text-sm text-gray-400">{t('status')}</th>
                                                    <th className="text-left p-3 text-sm text-gray-400"></th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {(!storage || storage.length === 0) ? (
                                                    <tr><td colSpan="8" className="p-8 text-center text-gray-500">No storage configured</td></tr>
                                                ) : storage.map((s, idx) => (
                                                    <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                        <td className="p-3">
                                                            <div className="flex items-center gap-2">
                                                                <span className={`w-2 h-2 rounded-full ${s.disable ? 'bg-gray-500' : 'bg-green-500'}`}></span>
                                                                <span className="font-medium text-white">{s.storage}</span>
                                                            </div>
                                                        </td>
                                                        <td className="p-3">
                                                            <span className="px-2 py-0.5 bg-proxmox-dark rounded text-xs text-gray-300">
                                                                {s.type}
                                                            </span>
                                                        </td>
                                                        <td className="p-3 text-sm text-gray-400 max-w-48">
                                                            <div className="flex flex-wrap gap-1">
                                                                {(s.content || '').split(',').map((c, i) => (
                                                                    <span key={i} className="px-1.5 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs">
                                                                        {c.trim()}
                                                                    </span>
                                                                ))}
                                                            </div>
                                                        </td>
                                                        <td className="p-3 font-mono text-sm text-gray-400 max-w-40 truncate">
                                                            {s.path || s.server || s.pool || s.portal || s.export || '-'}
                                                        </td>
                                                        <td className="p-3 text-sm text-gray-400">
                                                            {s.nodes || <span className="text-gray-500 italic">All</span>}
                                                        </td>
                                                        <td className="p-3">
                                                            {s.shared ? (
                                                                <span className="text-green-400">✓</span>
                                                            ) : (
                                                                <span className="text-gray-500">-</span>
                                                            )}
                                                        </td>
                                                        <td className="p-3">
                                                            {s.disable ? (
                                                                <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">{t('disabled')}</span>
                                                            ) : (
                                                                <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">{t('enabled')}</span>
                                                            )}
                                                        </td>
                                                        <td className="p-3">
                                                            <div className="flex gap-1">
                                                                <button 
                                                                    onClick={() => {
                                                                        setNewStorage({...s, enabled: !s.disable});
                                                                        setShowAddStorage(true);
                                                                    }}
                                                                    className="p-1.5 hover:bg-blue-500/20 rounded text-blue-400 transition-colors" 
                                                                    title="Edit"
                                                                >
                                                                    <Icons.Cog />
                                                                </button>
                                                                <button 
                                                                    onClick={() => deleteStorage(s.storage)} 
                                                                    className="p-1.5 hover:bg-red-500/20 rounded text-red-400 transition-colors" 
                                                                    title={t('delete')}
                                                                >
                                                                    <Icons.Trash />
                                                                </button>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>

                                {/* Multipath Easy Setup */}
                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                    <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                        <h3 className="font-semibold flex items-center gap-2">
                                            <Icons.Layers className="text-purple-400" />
                                            Multipath Redundancy
                                        </h3>
                                        <div className="flex gap-2">
                                            <button
                                                onClick={async () => {
                                                    setMultipathLoading(true);
                                                    try {
                                                        const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/multipath/status`);
                                                        if (res.ok) {
                                                            const data = await res.json();
                                                            setMultipathStatus(data);
                                                        }
                                                    } catch (e) {
                                                        console.error('Failed to get multipath status:', e);
                                                    }
                                                    setMultipathLoading(false);
                                                }}
                                                className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark hover:bg-proxmox-hover border border-proxmox-border rounded-lg text-sm"
                                            >
                                                <Icons.RefreshCw className={multipathLoading ? 'animate-spin' : ''} />
                                                {t('refresh')}
                                            </button>
                                            <button
                                                onClick={async () => {
                                                    // Load current status first
                                                    setMultipathLoading(true);
                                                    try {
                                                        const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/multipath/status`);
                                                        if (res.ok) {
                                                            setMultipathStatus(await res.json());
                                                        }
                                                    } catch (e) {}
                                                    setMultipathLoading(false);
                                                    setShowMultipathSetup(true);
                                                }}
                                                className="flex items-center gap-2 px-3 py-1.5 bg-purple-600 hover:bg-purple-700 rounded-lg text-sm"
                                            >
                                                <Icons.Zap /> Easy Setup
                                            </button>
                                        </div>
                                    </div>
                                    <div className="p-4">
                                        {!multipathStatus ? (
                                            <div className="text-center text-gray-500 py-4">
                                                <p>Click refresh to check multipath status across all nodes.</p>
                                                <p className="text-xs mt-2">Multipath provides redundant SAN/iSCSI connectivity for high availability.</p>
                                            </div>
                                        ) : (
                                            <div className="space-y-4">
                                                {/* Summary */}
                                                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                                                    <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                        <div className="text-2xl font-bold">{multipathStatus.summary?.nodes_with_multipath || 0}</div>
                                                        <div className="text-xs text-gray-400">Nodes with Multipath</div>
                                                    </div>
                                                    <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                        <div className="text-2xl font-bold">{multipathStatus.summary?.total_devices || 0}</div>
                                                        <div className="text-xs text-gray-400">Total Devices</div>
                                                    </div>
                                                    <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                        <div className="text-2xl font-bold text-green-400">{multipathStatus.summary?.healthy_devices || 0}</div>
                                                        <div className="text-xs text-gray-400">Healthy</div>
                                                    </div>
                                                    <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                        <div className="text-2xl font-bold text-yellow-400">{multipathStatus.summary?.degraded_devices || 0}</div>
                                                        <div className="text-xs text-gray-400">Degraded</div>
                                                    </div>
                                                    <div className="bg-proxmox-dark rounded-lg p-3 text-center">
                                                        <div className="text-2xl font-bold text-red-400">{multipathStatus.summary?.failed_devices || 0}</div>
                                                        <div className="text-xs text-gray-400">Failed</div>
                                                    </div>
                                                </div>

                                                {/* Per-Node Status */}
                                                {Object.entries(multipathStatus.nodes || {}).map(([nodeName, nodeData]) => (
                                                    <div key={nodeName} className="bg-proxmox-dark rounded-lg p-3">
                                                        <div className="flex items-center justify-between mb-2">
                                                            <span className="font-medium flex items-center gap-2">
                                                                <Icons.Server className="w-4 h-4" />
                                                                {nodeName}
                                                            </span>
                                                            <div className="flex items-center gap-2">
                                                                {nodeData.running ? (
                                                                    <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">multipathd running</span>
                                                                ) : nodeData.installed ? (
                                                                    <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 rounded text-xs">installed but stopped</span>
                                                                ) : (
                                                                    <span className="px-2 py-0.5 bg-gray-500/20 text-gray-400 rounded text-xs">not installed</span>
                                                                )}
                                                            </div>
                                                        </div>
                                                        {nodeData.devices && nodeData.devices.length > 0 && (
                                                            <div className="mt-2 space-y-1">
                                                                {nodeData.devices.map((dev, idx) => (
                                                                    <div key={idx} className="flex items-center justify-between text-sm bg-proxmox-card/50 rounded px-2 py-1">
                                                                        <span className="font-mono text-purple-400">/dev/mapper/{dev.name}</span>
                                                                        <div className="flex items-center gap-3">
                                                                            <span className="text-gray-400">{dev.size_gb} GB</span>
                                                                            <span className={`px-2 py-0.5 rounded text-xs ${
                                                                                dev.status === 'healthy' ? 'bg-green-500/20 text-green-400' :
                                                                                dev.status === 'degraded' ? 'bg-yellow-500/20 text-yellow-400' :
                                                                                'bg-red-500/20 text-red-400'
                                                                            }`}>
                                                                                {dev.active_paths}/{dev.total_paths} paths
                                                                            </span>
                                                                        </div>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        )}
                                                        {nodeData.error && (
                                                            <div className="text-xs text-red-400 mt-1">{nodeData.error}</div>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Multipath Easy Setup Modal */}
                                {showMultipathSetup && (
                                    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
                                            <div className="flex justify-between items-center p-4 border-b border-proxmox-border">
                                                <h3 className="text-lg font-semibold flex items-center gap-2">
                                                    <Icons.Zap className="text-purple-400" />
                                                    Multipath Easy Setup
                                                </h3>
                                                <button onClick={() => setShowMultipathSetup(false)} className="text-gray-400 hover:text-white">
                                                    <Icons.X />
                                                </button>
                                            </div>
                                            <div className="p-4 space-y-4">
                                                <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3 text-sm">
                                                    <p className="text-blue-400 font-medium mb-1">What this does:</p>
                                                    <ul className="text-gray-300 text-xs space-y-1 list-disc list-inside">
                                                        <li>Installs multipath-tools on all nodes (if not already installed)</li>
                                                        <li>Generates optimized multipath.conf for your storage vendor</li>
                                                        <li>Enables and starts multipathd service</li>
                                                        <li>Scans for existing multipath devices</li>
                                                    </ul>
                                                    <p className="text-green-400 text-xs mt-2">
                                                        ✓ Once active, all future iSCSI/FC connections automatically use multipath!
                                                    </p>
                                                </div>

                                                {/* Node Status Summary */}
                                                {multipathStatus && (
                                                    <div className="bg-proxmox-dark rounded-lg p-3">
                                                        <p className="text-sm font-medium mb-2">Current Node Status:</p>
                                                        <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-xs">
                                                            {Object.entries(multipathStatus.nodes || {}).map(([nodeName, nodeData]) => (
                                                                <div key={nodeName} className="flex items-center gap-2">
                                                                    <span className={`w-2 h-2 rounded-full ${nodeData.running ? 'bg-green-500' : nodeData.installed ? 'bg-yellow-500' : 'bg-gray-500'}`}></span>
                                                                    <span>{nodeName}</span>
                                                                    <span className="text-gray-500">
                                                                        {nodeData.running ? '(active)' : nodeData.installed ? '(stopped)' : '(not installed)'}
                                                                    </span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Node Selection */}
                                                <div className="bg-proxmox-dark rounded-lg p-3">
                                                    <div className="flex items-center justify-between mb-2">
                                                        <p className="text-sm font-medium">Target Nodes</p>
                                                        <button
                                                            onClick={() => {
                                                                if (multipathSelectedNodes === null) {
                                                                    // Switch to manual: start with all selected
                                                                    const allNodes = (clusterNodes || []).filter(n => n.online !== 0).map(n => n.node || n.name);
                                                                    setMultipathSelectedNodes(allNodes);
                                                                } else {
                                                                    setMultipathSelectedNodes(null);
                                                                }
                                                            }}
                                                            className="text-xs text-purple-400 hover:text-purple-300"
                                                        >
                                                            {multipathSelectedNodes === null ? 'Select individual nodes' : 'Select all nodes'}
                                                        </button>
                                                    </div>
                                                    {multipathSelectedNodes === null ? (
                                                        <p className="text-xs text-gray-400">All {(clusterNodes || []).filter(n => n.online !== 0).length} online nodes will be configured.</p>
                                                    ) : (
                                                        <div className="space-y-1">
                                                            {(clusterNodes || []).filter(n => n.online !== 0).map(n => {
                                                                const name = n.node || n.name;
                                                                const isSelected = multipathSelectedNodes.includes(name);
                                                                const nodeStatus = multipathStatus?.nodes?.[name];
                                                                return (
                                                                    <label key={name} className={`flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer hover:bg-proxmox-hover ${isSelected ? 'bg-purple-500/10' : ''}`}>
                                                                        <input
                                                                            type="checkbox"
                                                                            checked={isSelected}
                                                                            onChange={() => {
                                                                                setMultipathSelectedNodes(prev =>
                                                                                    isSelected ? prev.filter(x => x !== name) : [...prev, name]
                                                                                );
                                                                            }}
                                                                            className="accent-purple-500"
                                                                        />
                                                                        <Icons.Server className="w-3 h-3 text-gray-400" />
                                                                        <span className="text-sm">{name}</span>
                                                                        {nodeStatus && (
                                                                            <span className={`text-xs ml-auto ${nodeStatus.running ? 'text-green-500' : nodeStatus.installed ? 'text-yellow-500' : 'text-gray-500'}`}>
                                                                                {nodeStatus.running ? 'active' : nodeStatus.installed ? 'stopped' : 'not installed'}
                                                                            </span>
                                                                        )}
                                                                    </label>
                                                                );
                                                            })}
                                                            {multipathSelectedNodes.length === 0 && (
                                                                <p className="text-xs text-yellow-400 mt-1">Select at least one node</p>
                                                            )}
                                                        </div>
                                                    )}
                                                </div>

                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-2">Storage Vendor</label>
                                                    <select
                                                        value={multipathSetupData.vendor}
                                                        onChange={e => setMultipathSetupData({...multipathSetupData, vendor: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                    >
                                                        <option value="default">Default (Generic) - Works with most storage</option>
                                                        <option value="netapp">NetApp - ONTAP, E-Series, SolidFire</option>
                                                        <option value="emc">Dell EMC - VNX, Unity, PowerStore, XtremIO</option>
                                                        <option value="hpe">HPE - 3PAR, Primera, Nimble, MSA</option>
                                                        <option value="pure">Pure Storage - FlashArray, FlashBlade</option>
                                                        <option value="dell">Dell - Compellent, EqualLogic, PowerVault</option>
                                                    </select>
                                                </div>

                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-2">Load Balancing Policy</label>
                                                    <select
                                                        value={multipathSetupData.policy}
                                                        onChange={e => setMultipathSetupData({...multipathSetupData, policy: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                    >
                                                        <option value="service-time">Service Time (Recommended)</option>
                                                        <option value="round-robin">Round Robin</option>
                                                        <option value="queue-length">Queue Length</option>
                                                    </select>
                                                    <div className="text-xs text-gray-500 mt-2 space-y-1">
                                                        {multipathSetupData.policy === 'service-time' && (
                                                            <p>📊 <strong>Service Time:</strong> Routes I/O to the path with the shortest estimated service time. Best for mixed workloads - automatically adapts to path latency.</p>
                                                        )}
                                                        {multipathSetupData.policy === 'round-robin' && (
                                                            <p>🔄 <strong>Round Robin:</strong> Distributes I/O evenly across all paths in rotation. Good for symmetric active/active arrays with equal path performance.</p>
                                                        )}
                                                        {multipathSetupData.policy === 'queue-length' && (
                                                            <p>📋 <strong>Queue Length:</strong> Routes I/O to the path with the fewest pending requests. Good for paths with different throughput capabilities.</p>
                                                        )}
                                                    </div>
                                                </div>

                                                <div>
                                                    <label className="flex items-center gap-2 cursor-pointer">
                                                        <input
                                                            type="checkbox"
                                                            checked={multipathSetupData.skipExistingConfig !== true}
                                                            onChange={e => setMultipathSetupData({...multipathSetupData, skipExistingConfig: !e.target.checked})}
                                                            className="w-4 h-4 rounded"
                                                        />
                                                        <span className="text-sm">Write multipath.conf (uncheck to keep existing config)</span>
                                                    </label>
                                                    <p className="text-xs text-gray-500 mt-1 ml-6">
                                                        If unchecked, only installs/enables multipathd without changing existing configuration.
                                                    </p>
                                                </div>

                                                {multipathSetupResult && (
                                                    <div className={`rounded-lg p-3 ${multipathSetupResult.success ? 'bg-green-500/10 border border-green-500/30' : 'bg-red-500/10 border border-red-500/30'}`}>
                                                        <p className={`font-medium ${multipathSetupResult.success ? 'text-green-400' : 'text-red-400'}`}>
                                                            {multipathSetupResult.success ? '✓ Setup completed successfully!' : '✗ Setup had errors'}
                                                        </p>
                                                        {multipathSetupResult.error && (
                                                            <p className="text-red-400 text-sm mt-1">{multipathSetupResult.error}</p>
                                                        )}
                                                        <div className="mt-2 space-y-1 text-xs">
                                                            {multipathSetupResult.results?.map((r, idx) => (
                                                                <div key={idx} className="py-1">
                                                                    <div className="flex items-center gap-2">
                                                                        <span className={r.success ? 'text-green-400' : 'text-red-400'}>
                                                                            {r.success ? '✓' : '✗'}
                                                                        </span>
                                                                        <span className="font-medium">{r.node}</span>
                                                                        {r.skipped_config && <span className="text-yellow-400">(config preserved)</span>}
                                                                    </div>
                                                                    {r.error && <p className="text-red-400 text-xs ml-5 mt-0.5">{r.error}</p>}
                                                                    {r.steps && r.steps.length > 0 && !r.success && (
                                                                        <div className="ml-5 mt-1 space-y-0.5 text-gray-500">
                                                                            {r.steps.map((step, si) => (
                                                                                <div key={si} className="flex items-center gap-1">
                                                                                    <span className={step.success ? 'text-green-600' : 'text-red-500'}>{step.success ? '✓' : '✗'}</span>
                                                                                    <span>{step.action}</span>
                                                                                    {step.output && !step.success && <span className="text-red-500/70 truncate max-w-md">- {typeof step.output === 'string' ? step.output.substring(0, 150) : ''}</span>}
                                                                                </div>
                                                                            ))}
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            ))}
                                                        </div>
                                                        {multipathSetupResult.success && (
                                                            <p className="text-green-400 text-xs mt-2">
                                                                ✓ New iSCSI/FC LUNs will automatically use multipath redundancy!
                                                            </p>
                                                        )}
                                                    </div>
                                                )}
                                            </div>
                                            <div className="flex justify-between items-center gap-3 p-4 border-t border-proxmox-border">
                                                <div className="text-xs text-gray-500">
                                                    {multipathSelectedNodes === null 
                                                        ? `Deploys to all ${(clusterNodes || []).filter(n => n.online !== 0).length} online nodes`
                                                        : `Deploys to ${multipathSelectedNodes.length} selected node${multipathSelectedNodes.length !== 1 ? 's' : ''}`
                                                    }
                                                </div>
                                                <div className="flex gap-3">
                                                    <button
                                                        onClick={() => { setShowMultipathSetup(false); setMultipathSetupResult(null); setMultipathSelectedNodes(null); }}
                                                        className="px-4 py-2 bg-proxmox-border hover:bg-proxmox-hover rounded-lg"
                                                    >
                                                        {t('cancel')}
                                                    </button>
                                                    <button
                                                        onClick={async () => {
                                                            const targetNodes = multipathSelectedNodes !== null
                                                                ? multipathSelectedNodes
                                                                : (clusterNodes || []).filter(n => n.online !== 0).map(n => n.node || n.name);
                                                            if (targetNodes.length === 0) {
                                                                addToast('No nodes selected', 'error');
                                                                return;
                                                            }
                                                            setMultipathSetupResult(null);
                                                            addToast(`Starting multipath setup on ${targetNodes.length} node${targetNodes.length !== 1 ? 's' : ''}...`, 'info');
                                                            try {
                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/multipath/setup`, {
                                                                    method: 'POST',
                                                                    headers: { 'Content-Type': 'application/json' },
                                                                    body: JSON.stringify({
                                                                        ...multipathSetupData,
                                                                        nodes: targetNodes
                                                                    })
                                                                });
                                                                const data = await res.json();
                                                                if (!res.ok && !data.results) {
                                                                    // API returned error before reaching nodes (e.g. missing credentials)
                                                                    setMultipathSetupResult({ success: false, error: data.error || `Server error (${res.status})`, results: [] });
                                                                    addToast(data.error || 'Setup failed', 'error');
                                                                } else {
                                                                    setMultipathSetupResult(data);
                                                                    if (data.success) {
                                                                        addToast('Multipath setup completed!', 'success');
                                                                        // Wait a moment for services to stabilize, then refresh status
                                                                        addToast('Refreshing multipath status...', 'info');
                                                                        await new Promise(r => setTimeout(r, 2000));
                                                                        try {
                                                                            const statusRes = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/multipath/status`);
                                                                            if (statusRes.ok) {
                                                                                const statusData = await statusRes.json();
                                                                                setMultipathStatus(statusData);
                                                                                const running = statusData.summary?.nodes_with_multipath || 0;
                                                                                const total = statusData.summary?.total_nodes || 0;
                                                                                addToast(`Multipath active on ${running}/${total} nodes`, running === total ? 'success' : 'warning');
                                                                            }
                                                                        } catch (e) {
                                                                            console.error('Status refresh failed:', e);
                                                                        }
                                                                    } else {
                                                                        addToast(data.error || 'Multipath setup completed with errors', data.error ? 'error' : 'warning');
                                                                    }
                                                                }
                                                            } catch (e) {
                                                                addToast('Setup failed: ' + e.message, 'error');
                                                            }
                                                        }}
                                                        className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                                                        disabled={multipathSelectedNodes !== null && multipathSelectedNodes.length === 0}
                                                    >
                                                        <Icons.Zap className="w-4 h-4" />
                                                        {multipathSelectedNodes === null 
                                                            ? 'Deploy to All Nodes'
                                                            : `Deploy to ${multipathSelectedNodes.length} Node${multipathSelectedNodes.length !== 1 ? 's' : ''}`
                                                        }
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Add Storage Modal */}
                                {showAddStorage && (
                                    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setShowAddStorage(false)}>
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
                                            <div className="flex justify-between items-center p-4 border-b border-proxmox-border sticky top-0 bg-proxmox-card z-10">
                                                <h3 className="text-lg font-semibold flex items-center gap-2">
                                                    <Icons.HardDrive />
                                                    {newStorage.storage ? `Edit: ${newStorage.storage}` : `Add: ${storageTypes.find(s => s.id === newStorage.type)?.label || 'Storage'}`}
                                                </h3>
                                                <button onClick={() => setShowAddStorage(false)} className="p-1.5 hover:bg-proxmox-dark rounded-lg transition-colors"><Icons.X /></button>
                                            </div>
                                            
                                            {/* Storage Type Selection */}
                                            <div className="p-4 border-b border-proxmox-border">
                                                <label className="block text-sm text-gray-400 mb-2">Type</label>
                                                <div className="grid grid-cols-5 gap-2">
                                                    {storageTypes.map(st => (
                                                        <button key={st.id} onClick={() => {
                                                            setNewStorage({type: st.id, storage: '', content: 'images,rootdir', enabled: true});
                                                            setScanResults([]); // Clear scan results when type changes
                                                        }}
                                                            className={`p-2 rounded-lg border text-xs flex flex-col items-center gap-1 ${newStorage.type === st.id ? 'border-proxmox-orange bg-proxmox-orange/20' : 'border-proxmox-border hover:bg-proxmox-dark'}`}>
                                                            <span className="text-lg">{st.icon}</span> {st.label}
                                                        </button>
                                                    ))}
                                                </div>
                                            </div>

                                            <div className="p-4 space-y-4">
                                                {/* Common Fields */}
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">ID *</label>
                                                        <input value={newStorage.storage || ''} onChange={e => setNewStorage({...newStorage, storage: e.target.value})} placeholder="storage-name" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Nodes</label>
                                                        <select value={newStorage.nodes || ''} onChange={e => setNewStorage({...newStorage, nodes: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                            <option value="">All (No restrictions)</option>
                                                            {(clusterNodes || []).map(n => <option key={n.name} value={n.name}>{n.name}</option>)}
                                                        </select>
                                                    </div>
                                                </div>

                                                {/* iSCSI Fields */}
                                                {newStorage.type === 'iscsi' && (
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Portal *</label>
                                                            <div className="flex gap-2">
                                                                <input value={newStorage.portal || ''} onChange={e => setNewStorage({...newStorage, portal: e.target.value})} placeholder="192.168.1.100" className="flex-1 bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                                <button 
                                                                    onClick={() => scanStorage('iscsi')} 
                                                                    disabled={!newStorage.portal || scanning}
                                                                    className="px-3 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded text-sm whitespace-nowrap"
                                                                >
                                                                    {scanning ? '...' : 'Scan'}
                                                                </button>
                                                            </div>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Target *</label>
                                                            {scanResults.length > 0 && newStorage.type === 'iscsi' ? (
                                                                <select 
                                                                    value={newStorage.target || ''} 
                                                                    onChange={e => setNewStorage({...newStorage, target: e.target.value})} 
                                                                    className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono"
                                                                >
                                                                    <option value="">Select target...</option>
                                                                    {scanResults.map((r, i) => (
                                                                        <option key={i} value={r.target}>{r.target}</option>
                                                                    ))}
                                                                </select>
                                                            ) : (
                                                                <input value={newStorage.target || ''} onChange={e => setNewStorage({...newStorage, target: e.target.value})} placeholder="iqn.2024..." className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                            )}
                                                        </div>
                                                        <div className="flex items-center gap-4 col-span-2">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.enabled !== false} onChange={e => setNewStorage({...newStorage, enabled: e.target.checked})} className="rounded" /> Enable
                                                            </label>
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.comstar_tg || false} onChange={e => setNewStorage({...newStorage, comstar_tg: e.target.checked})} className="rounded" /> Use LUNs directly
                                                            </label>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* LVM Fields */}
                                                {newStorage.type === 'lvm' && (
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Base storage (for Shared LVM)</label>
                                                            <select value={newStorage.baseStorage || ''} onChange={e => {
                                                                const baseStorage = e.target.value;
                                                                // NS: If base storage is selected, it becomes shared automatically
                                                                setNewStorage({...newStorage, baseStorage, base: '', shared: baseStorage ? true : newStorage.shared});
                                                                // Clear scan results when base changes
                                                                setScanResults([]);
                                                            }} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="">Existing volume groups (local)</option>
                                                                {storage.filter(s => s.type === 'iscsi').map(s => <option key={s.storage} value={s.storage}>iSCSI: {s.storage}</option>)}
                                                            </select>
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.enabled !== false} onChange={e => setNewStorage({...newStorage, enabled: e.target.checked})} className="rounded" /> Enable
                                                            </label>
                                                        </div>
                                                        
                                                        {/* Shared LVM Info */}
                                                        {newStorage.baseStorage && (
                                                            <div className="col-span-2 p-3 bg-blue-900/30 border border-blue-500/50 rounded text-sm text-blue-300">
                                                                <strong>Shared LVM:</strong> Select a LUN from "{newStorage.baseStorage}" below. 
                                                                The volume group will be created on or use the selected LUN.
                                                                All cluster nodes must have access to the iSCSI target.
                                                            </div>
                                                        )}
                                                        
                                                        {/* LUN Selection for Shared LVM */}
                                                        {newStorage.baseStorage && (
                                                            <div className="col-span-2">
                                                                <label className="block text-sm text-gray-400 mb-1">Select LUN *</label>
                                                                <div className="flex gap-2">
                                                                    <select 
                                                                        value={newStorage.base || ''} 
                                                                        onChange={e => setNewStorage({...newStorage, base: e.target.value})}
                                                                        className="flex-1 bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono"
                                                                    >
                                                                        <option value="">Select LUN...</option>
                                                                        {/* NS: volid from Proxmox already includes storage name like "iscsi-storage:0.0.0.1.lun-0" */}
                                                                        {scanResults.filter(l => l.volid).map((lun, i) => (
                                                                            <option key={i} value={lun.volid}>
                                                                                {lun.volid} {lun.size ? `(${(lun.size / 1024 / 1024 / 1024).toFixed(1)} GB)` : ''}
                                                                            </option>
                                                                        ))}
                                                                    </select>
                                                                    <button 
                                                                        onClick={async () => {
                                                                            // Fetch LUNs from iSCSI storage
                                                                            setScanning(true);
                                                                            try {
                                                                                const res = await authFetch(`${API_URL}/clusters/${clusterId}/datastores/${newStorage.baseStorage}/content`);
                                                                                if (res?.ok) {
                                                                                    const luns = await res.json();
                                                                                    console.log('LUNs from', newStorage.baseStorage, ':', luns);
                                                                                    setScanResults(luns || []);
                                                                                } else {
                                                                                    addToast('Failed to scan LUNs', 'error');
                                                                                }
                                                                            } catch (e) {
                                                                                console.error('Error fetching LUNs:', e);
                                                                                addToast('Error scanning LUNs', 'error');
                                                                            }
                                                                            setScanning(false);
                                                                        }}
                                                                        disabled={scanning}
                                                                        className="px-3 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded text-sm whitespace-nowrap"
                                                                    >
                                                                        {scanning ? '...' : 'Scan LUNs'}
                                                                    </button>
                                                                </div>
                                                                {scanResults.length === 0 && !scanning && (
                                                                    <p className="text-xs text-gray-500 mt-1">Click "Scan LUNs" to discover available LUNs</p>
                                                                )}
                                                                {newStorage.baseStorage && !newStorage.base && scanResults.length > 0 && (
                                                                    <p className="text-xs text-yellow-400 mt-1">⚠️ Select a LUN to continue</p>
                                                                )}
                                                            </div>
                                                        )}
                                                        
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Volume group name *</label>
                                                            <div className="flex gap-2">
                                                                {!newStorage.baseStorage && scanResults.length > 0 && newStorage.type === 'lvm' ? (
                                                                    <select 
                                                                        value={newStorage.vgname || ''} 
                                                                        onChange={e => setNewStorage({...newStorage, vgname: e.target.value})} 
                                                                        className="flex-1 bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                                                    >
                                                                        <option value="">Select VG...</option>
                                                                        {scanResults.filter(r => r.vg).map((r, i) => (
                                                                            <option key={i} value={r.vg}>{r.vg} ({(r.size / 1024 / 1024 / 1024).toFixed(1)} GB)</option>
                                                                        ))}
                                                                    </select>
                                                                ) : (
                                                                    <input 
                                                                        value={newStorage.vgname || ''} 
                                                                        onChange={e => setNewStorage({...newStorage, vgname: e.target.value})} 
                                                                        placeholder={newStorage.baseStorage ? "shared-vg" : "pve"} 
                                                                        className="flex-1 bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" 
                                                                    />
                                                                )}
                                                                {!newStorage.baseStorage && (
                                                                    <button 
                                                                        onClick={() => scanStorage('lvm')} 
                                                                        disabled={scanning}
                                                                        className="px-3 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded text-sm whitespace-nowrap"
                                                                    >
                                                                        {scanning ? '...' : 'Scan'}
                                                                    </button>
                                                                )}
                                                            </div>
                                                            {newStorage.baseStorage && !newStorage.vgname && (
                                                                <p className="text-xs text-yellow-400 mt-1">⚠️ Enter a volume group name</p>
                                                            )}
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input 
                                                                    type="checkbox" 
                                                                    checked={newStorage.shared || false} 
                                                                    onChange={e => setNewStorage({...newStorage, shared: e.target.checked})} 
                                                                    disabled={!!newStorage.baseStorage}
                                                                    className="rounded" 
                                                                /> Shared {newStorage.baseStorage && '(auto)'}
                                                            </label>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Content</label>
                                                            <select value={newStorage.content || 'images,rootdir'} onChange={e => setNewStorage({...newStorage, content: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="images,rootdir">Disk image, Container</option>
                                                                <option value="images">Disk image</option>
                                                                <option value="rootdir">Container</option>
                                                            </select>
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm" title="Wipe disk when deleting volumes (more secure, slower)">
                                                                <input type="checkbox" checked={newStorage.saferemove || false} onChange={e => setNewStorage({...newStorage, saferemove: e.target.checked})} className="rounded" /> Wipe on Delete
                                                            </label>
                                                        </div>
                                                        
                                                        {/* Snapshot as Volume Chain - PVE 9+ Feature for LVM */}
                                                        <div className="col-span-2 p-3 bg-proxmox-dark border border-proxmox-border rounded">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input 
                                                                    type="checkbox" 
                                                                    checked={newStorage['snapshot-as-volume-chain'] || false} 
                                                                    onChange={e => setNewStorage({...newStorage, 'snapshot-as-volume-chain': e.target.checked})} 
                                                                    className="rounded" 
                                                                />
                                                                <span className="font-medium">Snapshot as Volume Chain</span>
                                                                <span className="text-xs px-1.5 py-0.5 bg-green-600/30 text-green-400 rounded">PVE 9+</span>
                                                            </label>
                                                            <p className="text-xs text-gray-500 mt-1 ml-6">
                                                                Uses separate volumes for snapshot data instead of internal LVM snapshots. 
                                                                This provides better performance and compatibility.
                                                            </p>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* LVM-Thin Fields */}
                                                {newStorage.type === 'lvmthin' && (
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Volume group *</label>
                                                            <div className="flex gap-2">
                                                                {scanResults.length > 0 && newStorage.type === 'lvmthin' && !newStorage.vgname ? (
                                                                    <select 
                                                                        value={newStorage.vgname || ''} 
                                                                        onChange={e => setNewStorage({...newStorage, vgname: e.target.value})} 
                                                                        className="flex-1 bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                                                    >
                                                                        <option value="">Select VG...</option>
                                                                        {scanResults.filter(r => r.vg).map((r, i) => (
                                                                            <option key={i} value={r.vg}>{r.vg}</option>
                                                                        ))}
                                                                    </select>
                                                                ) : (
                                                                    <input value={newStorage.vgname || ''} onChange={e => setNewStorage({...newStorage, vgname: e.target.value})} placeholder="pve" className="flex-1 bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                                )}
                                                                <button 
                                                                    onClick={() => scanStorage('lvm')} 
                                                                    disabled={scanning}
                                                                    className="px-3 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded text-sm whitespace-nowrap"
                                                                >
                                                                    {scanning ? '...' : 'Scan VG'}
                                                                </button>
                                                            </div>
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.enabled !== false} onChange={e => setNewStorage({...newStorage, enabled: e.target.checked})} className="rounded" /> Enable
                                                            </label>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Thin Pool *</label>
                                                            <div className="flex gap-2">
                                                                {scanResults.length > 0 && newStorage.vgname && scanResults.some(r => r.lv) ? (
                                                                    <select 
                                                                        value={newStorage.thinpool || ''} 
                                                                        onChange={e => setNewStorage({...newStorage, thinpool: e.target.value})} 
                                                                        className="flex-1 bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                                                    >
                                                                        <option value="">Select pool...</option>
                                                                        {scanResults.filter(r => r.lv).map((r, i) => (
                                                                            <option key={i} value={r.lv}>{r.lv} ({(r.size / 1024 / 1024 / 1024).toFixed(1)} GB, {r.used_percent}% used)</option>
                                                                        ))}
                                                                    </select>
                                                                ) : (
                                                                    <input value={newStorage.thinpool || ''} onChange={e => setNewStorage({...newStorage, thinpool: e.target.value})} placeholder="data" className="flex-1 bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                                )}
                                                                {newStorage.vgname && (
                                                                    <button 
                                                                        onClick={() => scanStorage('lvmthin')} 
                                                                        disabled={scanning || !newStorage.vgname}
                                                                        className="px-3 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded text-sm whitespace-nowrap"
                                                                    >
                                                                        {scanning ? '...' : 'Scan'}
                                                                    </button>
                                                                )}
                                                            </div>
                                                        </div>
                                                        <div></div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Content</label>
                                                            <select value={newStorage.content || 'images,rootdir'} onChange={e => setNewStorage({...newStorage, content: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="images,rootdir">Disk image, Container</option>
                                                                <option value="images">Disk image</option>
                                                                <option value="rootdir">Container</option>
                                                            </select>
                                                        </div>
                                                        <div></div>
                                                        
                                                        {/* Snapshot as Volume Chain - PVE 9+ Feature */}
                                                        <div className="col-span-2 p-3 bg-proxmox-dark border border-proxmox-border rounded">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input 
                                                                    type="checkbox" 
                                                                    checked={newStorage['snapshot-as-volume-chain'] || false} 
                                                                    onChange={e => setNewStorage({...newStorage, 'snapshot-as-volume-chain': e.target.checked})} 
                                                                    className="rounded" 
                                                                />
                                                                <span className="font-medium">Snapshot as Volume Chain</span>
                                                                <span className="text-xs px-1.5 py-0.5 bg-green-600/30 text-green-400 rounded">PVE 9+</span>
                                                            </label>
                                                            <p className="text-xs text-gray-500 mt-1 ml-6">
                                                                Uses separate volumes for snapshot data instead of internal snapshots. 
                                                                Improves performance and allows online snapshots for LVM-thin.
                                                            </p>
                                                        </div>
                                                        
                                                        {/* LVM-thin cannot be shared warning */}
                                                        <div className="col-span-2 p-2 bg-yellow-900/30 border border-yellow-500/50 rounded text-xs text-yellow-300">
                                                            ⚠️ LVM-thin storage cannot be shared between cluster nodes. For shared block storage, use regular LVM on iSCSI or Ceph RBD.
                                                        </div>
                                                    </div>
                                                )}

                                                {/* BTRFS Fields */}
                                                {newStorage.type === 'btrfs' && (
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Path *</label>
                                                            <input value={newStorage.path || ''} onChange={e => setNewStorage({...newStorage, path: e.target.value})} placeholder="/mnt/btrfs" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.enabled !== false} onChange={e => setNewStorage({...newStorage, enabled: e.target.checked})} className="rounded" /> Enable
                                                            </label>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Content</label>
                                                            <select value={newStorage.content || 'images,rootdir'} onChange={e => setNewStorage({...newStorage, content: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="images,rootdir">Disk image, Container</option>
                                                                <option value="images">Disk image</option>
                                                                <option value="rootdir">Container</option>
                                                            </select>
                                                        </div>
                                                        <div></div>
                                                        <div className="col-span-2 p-3 bg-blue-900/30 border border-blue-500/50 rounded text-sm text-blue-300">
                                                            BTRFS integration is currently a technology preview.
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Preallocation</label>
                                                            <select value={newStorage.preallocation || ''} onChange={e => setNewStorage({...newStorage, preallocation: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="">Default</option>
                                                                <option value="off">Off</option>
                                                                <option value="metadata">Metadata</option>
                                                                <option value="falloc">Falloc</option>
                                                                <option value="full">Full</option>
                                                            </select>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* NFS Fields */}
                                                {newStorage.type === 'nfs' && (
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Server *</label>
                                                            <div className="flex gap-2">
                                                                <input value={newStorage.server || ''} onChange={e => setNewStorage({...newStorage, server: e.target.value})} placeholder="192.168.1.100" className="flex-1 bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                                <button 
                                                                    onClick={() => scanStorage('nfs')} 
                                                                    disabled={!newStorage.server || scanning}
                                                                    className="px-3 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded text-sm whitespace-nowrap"
                                                                >
                                                                    {scanning ? '...' : 'Scan'}
                                                                </button>
                                                            </div>
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.enabled !== false} onChange={e => setNewStorage({...newStorage, enabled: e.target.checked})} className="rounded" /> Enable
                                                            </label>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Export *</label>
                                                            {scanResults.length > 0 && newStorage.type === 'nfs' ? (
                                                                <select 
                                                                    value={newStorage.export || ''} 
                                                                    onChange={e => setNewStorage({...newStorage, export: e.target.value})} 
                                                                    className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono"
                                                                >
                                                                    <option value="">Select export...</option>
                                                                    {scanResults.map((r, i) => (
                                                                        <option key={i} value={r.path}>{r.path} {r.options ? `(${r.options})` : ''}</option>
                                                                    ))}
                                                                </select>
                                                            ) : (
                                                                <input value={newStorage.export || ''} onChange={e => setNewStorage({...newStorage, export: e.target.value})} placeholder="/export/share" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                            )}
                                                        </div>
                                                        <div></div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Content</label>
                                                            <select value={newStorage.content || 'images'} onChange={e => setNewStorage({...newStorage, content: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="images">Disk image</option>
                                                                <option value="images,rootdir">Disk image, Container</option>
                                                                <option value="backup">Backup</option>
                                                                <option value="iso">ISO image</option>
                                                                <option value="vztmpl">Container template</option>
                                                                <option value="snippets">Snippets</option>
                                                            </select>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">NFS Version</label>
                                                            <select value={newStorage.options || ''} onChange={e => setNewStorage({...newStorage, options: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="">Default</option>
                                                                <option value="vers=3">NFSv3</option>
                                                                <option value="vers=4">NFSv4</option>
                                                                <option value="vers=4.1">NFSv4.1</option>
                                                                <option value="vers=4.2">NFSv4.2</option>
                                                            </select>
                                                        </div>
                                                        <div className="col-span-2 p-3 bg-proxmox-dark border border-proxmox-border rounded">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input 
                                                                    type="checkbox" 
                                                                    checked={newStorage['snapshot-as-volume-chain'] || false} 
                                                                    onChange={e => setNewStorage({...newStorage, 'snapshot-as-volume-chain': e.target.checked})} 
                                                                    className="rounded" 
                                                                />
                                                                <span className="font-medium">Snapshot as Volume Chain</span>
                                                                <span className="text-xs px-1.5 py-0.5 bg-green-600/30 text-green-400 rounded">PVE 9+</span>
                                                            </label>
                                                            <p className="text-xs text-gray-500 mt-1 ml-6">
                                                                Uses separate qcow2 files for snapshot data instead of internal qcow2 snapshots.
                                                            </p>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Preallocation</label>
                                                            <select value={newStorage.preallocation || ''} onChange={e => setNewStorage({...newStorage, preallocation: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="">Default</option>
                                                                <option value="off">Off</option>
                                                                <option value="metadata">Metadata</option>
                                                                <option value="falloc">Falloc</option>
                                                                <option value="full">Full</option>
                                                            </select>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* SMB/CIFS Fields */}
                                                {newStorage.type === 'cifs' && (
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Server *</label>
                                                            <input value={newStorage.server || ''} onChange={e => setNewStorage({...newStorage, server: e.target.value})} placeholder="192.168.1.100" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.enabled !== false} onChange={e => setNewStorage({...newStorage, enabled: e.target.checked})} className="rounded" /> Enable
                                                            </label>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Username</label>
                                                            <input value={newStorage.username || ''} onChange={e => setNewStorage({...newStorage, username: e.target.value})} placeholder="Guest user" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Content</label>
                                                            <select value={newStorage.content || 'images'} onChange={e => setNewStorage({...newStorage, content: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="images">Disk image</option>
                                                                <option value="images,rootdir">Disk image, Container</option>
                                                                <option value="backup">Backup</option>
                                                                <option value="iso">ISO image</option>
                                                            </select>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Password</label>
                                                            <input type="password" value={newStorage.password || ''} onChange={e => setNewStorage({...newStorage, password: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Domain</label>
                                                            <input value={newStorage.domain || ''} onChange={e => setNewStorage({...newStorage, domain: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Share *</label>
                                                            <input value={newStorage.share || ''} onChange={e => setNewStorage({...newStorage, share: e.target.value})} placeholder="share-name" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Subdirectory</label>
                                                            <input value={newStorage.subdir || ''} onChange={e => setNewStorage({...newStorage, subdir: e.target.value})} placeholder="/some/path" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Preallocation</label>
                                                            <select value={newStorage.preallocation || ''} onChange={e => setNewStorage({...newStorage, preallocation: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="">Default</option>
                                                                <option value="off">Off</option>
                                                                <option value="metadata">Metadata</option>
                                                                <option value="full">Full</option>
                                                            </select>
                                                        </div>
                                                        <div className="col-span-2 p-3 bg-proxmox-dark border border-proxmox-border rounded">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input 
                                                                    type="checkbox" 
                                                                    checked={newStorage['snapshot-as-volume-chain'] || false} 
                                                                    onChange={e => setNewStorage({...newStorage, 'snapshot-as-volume-chain': e.target.checked})} 
                                                                    className="rounded" 
                                                                />
                                                                <span className="font-medium">Snapshot as Volume Chain</span>
                                                                <span className="text-xs px-1.5 py-0.5 bg-green-600/30 text-green-400 rounded">PVE 9+</span>
                                                            </label>
                                                            <p className="text-xs text-gray-500 mt-1 ml-6">
                                                                Uses separate qcow2 files for snapshot data instead of internal qcow2 snapshots.
                                                            </p>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Directory Fields */}
                                                {newStorage.type === 'dir' && (
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Directory *</label>
                                                            <input value={newStorage.path || ''} onChange={e => setNewStorage({...newStorage, path: e.target.value})} placeholder="/mnt/storage" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.enabled !== false} onChange={e => setNewStorage({...newStorage, enabled: e.target.checked})} className="rounded" /> Enable
                                                            </label>
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.shared || false} onChange={e => setNewStorage({...newStorage, shared: e.target.checked})} className="rounded" /> Shared
                                                            </label>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Content</label>
                                                            <select value={newStorage.content || 'images,rootdir,vztmpl,backup,iso,snippets'} onChange={e => setNewStorage({...newStorage, content: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="images,rootdir,vztmpl,backup,iso,snippets">All</option>
                                                                <option value="images,rootdir">Disk image, Container</option>
                                                                <option value="backup">Backup</option>
                                                                <option value="iso">ISO image</option>
                                                                <option value="vztmpl">Container template</option>
                                                            </select>
                                                        </div>
                                                        <div></div>
                                                        <div className="col-span-2 p-3 bg-proxmox-dark border border-proxmox-border rounded">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input 
                                                                    type="checkbox" 
                                                                    checked={newStorage['snapshot-as-volume-chain'] || false} 
                                                                    onChange={e => setNewStorage({...newStorage, 'snapshot-as-volume-chain': e.target.checked})} 
                                                                    className="rounded" 
                                                                />
                                                                <span className="font-medium">Snapshot as Volume Chain</span>
                                                                <span className="text-xs px-1.5 py-0.5 bg-green-600/30 text-green-400 rounded">PVE 9+</span>
                                                            </label>
                                                            <p className="text-xs text-gray-500 mt-1 ml-6">
                                                                Uses separate qcow2 files for snapshot data instead of internal qcow2 snapshots.
                                                            </p>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* PBS Fields */}
                                                {newStorage.type === 'pbs' && (
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Server *</label>
                                                            <input value={newStorage.server || ''} onChange={e => setNewStorage({...newStorage, server: e.target.value})} placeholder="pbs.example.com" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.enabled !== false} onChange={e => setNewStorage({...newStorage, enabled: e.target.checked})} className="rounded" /> Enable
                                                            </label>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Username *</label>
                                                            <input value={newStorage.username || ''} onChange={e => setNewStorage({...newStorage, username: e.target.value})} placeholder="user@pbs" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Password *</label>
                                                            <input type="password" value={newStorage.password || ''} onChange={e => setNewStorage({...newStorage, password: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Datastore *</label>
                                                            <input value={newStorage.datastore || ''} onChange={e => setNewStorage({...newStorage, datastore: e.target.value})} placeholder="store1" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Fingerprint</label>
                                                            <input value={newStorage.fingerprint || ''} onChange={e => setNewStorage({...newStorage, fingerprint: e.target.value})} placeholder="optional" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono text-xs" />
                                                        </div>
                                                    </div>
                                                )}

                                                {/* ZFS Pool Fields */}
                                                {newStorage.type === 'zfspool' && (
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Pool *</label>
                                                            <input value={newStorage.pool || ''} onChange={e => setNewStorage({...newStorage, pool: e.target.value})} placeholder="rpool/data" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.enabled !== false} onChange={e => setNewStorage({...newStorage, enabled: e.target.checked})} className="rounded" /> Enable
                                                            </label>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Content</label>
                                                            <select value={newStorage.content || 'images,rootdir'} onChange={e => setNewStorage({...newStorage, content: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm">
                                                                <option value="images,rootdir">Disk image, Container</option>
                                                                <option value="images">Disk image</option>
                                                                <option value="rootdir">Container</option>
                                                            </select>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* ESXi Fields */}
                                                {newStorage.type === 'esxi' && (
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Server *</label>
                                                            <input value={newStorage.server || ''} onChange={e => setNewStorage({...newStorage, server: e.target.value})} placeholder="IP address or hostname" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.enabled !== false} onChange={e => setNewStorage({...newStorage, enabled: e.target.checked})} className="rounded" /> Enable
                                                            </label>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Username *</label>
                                                            <input value={newStorage.username || ''} onChange={e => setNewStorage({...newStorage, username: e.target.value})} placeholder="root" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm">
                                                                <input type="checkbox" checked={newStorage.skip_cert_verification || false} onChange={e => setNewStorage({...newStorage, skip_cert_verification: e.target.checked})} className="rounded" /> Skip Certificate Verification
                                                            </label>
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Password *</label>
                                                            <input type="password" value={newStorage.password || ''} onChange={e => setNewStorage({...newStorage, password: e.target.value})} className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                        </div>
                                                    </div>
                                                )}
                                            </div>

                                            <div className="flex justify-end gap-3 p-4 border-t border-proxmox-border sticky bottom-0 bg-proxmox-card">
                                                <button 
                                                    onClick={() => {
                                                        setShowAddStorage(false);
                                                        setNewStorage({ type: 'dir', storage: '', path: '', content: 'images,rootdir', enabled: true });
                                                    }} 
                                                    className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg text-sm transition-colors"
                                                >
                                                    {t('cancel')}
                                                </button>
                                                <button 
                                                    onClick={createStorage} 
                                                    disabled={!newStorage.storage}
                                                    className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm text-white transition-colors"
                                                >
                                                    {newStorage.storage && storage.some(s => s.storage === newStorage.storage) ? t('save') : t('add')}
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* SDN - Software Defined Networking - NS Feb 2026 */}
                        {activeSection === 'sdn' && (
                            <div className="space-y-4">
                                {!sdnData.available ? (
                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-8 text-center">
                                        <Icons.Network className="w-12 h-12 mx-auto mb-4 text-gray-500" />
                                        <h3 className="text-lg font-semibold mb-2">{t('sdnNotAvailable') || 'SDN Not Available'}</h3>
                                        <p className="text-gray-400 text-sm mb-4">
                                            {sdnData.error || t('sdnNotConfigured') || 'Software Defined Networking is not configured on this cluster.'}
                                        </p>
                                        
                                        {/* Troubleshooting hints */}
                                        <div className="bg-proxmox-dark rounded-lg p-4 text-left mb-4 max-w-md mx-auto">
                                            <p className="text-xs text-gray-400 mb-2 font-medium">Troubleshooting:</p>
                                            <ul className="text-xs text-gray-500 space-y-1 list-disc list-inside">
                                                <li>SDN requires Proxmox VE 6.2 or newer</li>
                                                <li>Install: <code className="text-orange-400">apt install libpve-network-perl</code></li>
                                                <li>Enable SDN in Datacenter ↑ SDN in Proxmox UI</li>
                                                <li>API user needs SDN.Audit permission</li>
                                            </ul>
                                        </div>
                                        
                                        <div className="flex gap-3 justify-center">
                                            <a 
                                                href="https://pve.proxmox.com/wiki/Software_Defined_Network" 
                                                target="_blank" 
                                                rel="noopener noreferrer"
                                                className="text-blue-400 hover:underline text-sm"
                                            >
                                                {t('learnMore') || 'Learn more about Proxmox SDN'} ↑
                                            </a>
                                            <button
                                                onClick={() => {
                                                    console.log('SDN Data:', sdnData);
                                                    console.log('SDN Debug:', sdnData.debug);
                                                    alert(`SDN Debug Info:\n\nAvailable: ${sdnData.available}\nSDN Status: ${sdnData.debug?.sdn_status || 'N/A'}\nZones Status: ${sdnData.debug?.zones_status || 'N/A'}\nError: ${sdnData.debug?.error || sdnData.debug?.zones_error || 'None'}\n\nCheck browser console (F12) for full details.`);
                                                }}
                                                className="text-gray-400 hover:text-white text-sm"
                                            >
                                                Debug Info
                                            </button>
                                        </div>
                                    </div>
                                ) : (
                                    <>
                                        {/* SDN Status Banner */}
                                        {/* Apply Button - always visible */}
                                        <div className={`rounded-xl p-4 flex items-center justify-between ${sdnData.pending ? 'bg-yellow-500/10 border border-yellow-500/30' : 'bg-proxmox-card border border-proxmox-border'}`}>
                                            <div className="flex items-center gap-3">
                                                {sdnData.pending ? (
                                                    <>
                                                        <Icons.AlertTriangle className="text-yellow-500" />
                                                        <span className="text-yellow-500">
                                                            {t('sdnPendingChanges') || 'There are pending SDN changes that need to be applied.'}
                                                        </span>
                                                    </>
                                                ) : (
                                                    <>
                                                        <Icons.CheckCircle className="text-green-500" />
                                                        <span className="text-gray-400">
                                                            {t('sdnConfigSynced') || 'SDN configuration is in sync with all nodes.'}
                                                        </span>
                                                    </>
                                                )}
                                            </div>
                                            <button
                                                onClick={async () => {
                                                    try {
                                                        addToast(t('applyingSDN') || 'Applying SDN configuration to all nodes...', 'info');
                                                        const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/apply`, { method: 'POST' });
                                                        if (res.ok) {
                                                            addToast(t('sdnApplied') || 'SDN configuration applied to all nodes', 'success');
                                                            // Short delay then refresh
                                                            setTimeout(() => fetchAllData(), 1000);
                                                        } else {
                                                            const err = await res.json();
                                                            addToast(err.error || 'Failed to apply SDN', 'error');
                                                        }
                                                    } catch (e) {
                                                        addToast('Failed to apply SDN', 'error');
                                                    }
                                                }}
                                                className={`px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 ${
                                                    sdnData.pending 
                                                        ? 'bg-yellow-500 hover:bg-yellow-600 text-black' 
                                                        : 'bg-proxmox-orange hover:bg-orange-600 text-white'
                                                }`}
                                            >
                                                <Icons.RefreshCw className="w-4 h-4" />
                                                {t('applyChanges') || 'Apply / Reload'}
                                            </button>
                                        </div>

                                        {/* Zones */}
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                            <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                <h3 className="font-semibold flex items-center gap-2">
                                                    <Icons.Layers className="w-5 h-5" />
                                                    {t('sdnZones') || 'Zones'}
                                                </h3>
                                                <button 
                                                    onClick={() => { setNewZone({ zone: '', type: 'simple' }); setShowAddZone(true); }}
                                                    className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                                >
                                                    <Icons.Plus /> {t('add')}
                                                </button>
                                            </div>
                                            {sdnData.zones.length === 0 ? (
                                                <div className="p-8 text-center text-gray-500">
                                                    <p>{t('noZones') || 'No zones configured'}</p>
                                                </div>
                                            ) : (
                                                <table className="w-full">
                                                    <thead className="bg-proxmox-dark">
                                                        <tr>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('zone') || 'Zone'}</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('type') || 'Type'}</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">MTU</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">Nodes</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('vnets') || 'VNets'}</th>
                                                            <th className="text-right p-3 text-sm text-gray-400">{t('actions')}</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {sdnData.zones.map(zone => (
                                                            <tr key={zone.zone} className="border-t border-proxmox-border hover:bg-proxmox-hover">
                                                                <td className="p-3">
                                                                    <span className="font-medium text-white">{zone.zone}</span>
                                                                </td>
                                                                <td className="p-3">
                                                                    <span className={`px-2 py-1 rounded text-xs ${
                                                                        zone.type === 'simple' ? 'bg-green-500/20 text-green-400' :
                                                                        zone.type === 'vlan' ? 'bg-blue-500/20 text-blue-400' :
                                                                        zone.type === 'vxlan' ? 'bg-purple-500/20 text-purple-400' :
                                                                        zone.type === 'evpn' ? 'bg-orange-500/20 text-orange-400' :
                                                                        'bg-gray-500/20 text-gray-400'
                                                                    }`}>
                                                                        {zone.type}
                                                                    </span>
                                                                </td>
                                                                <td className="p-3 text-gray-400">{zone.mtu || '-'}</td>
                                                                <td className="p-3 text-gray-400">{zone.nodes || 'all'}</td>
                                                                <td className="p-3 text-gray-400">
                                                                    {sdnData.vnets.filter(v => v.zone === zone.zone).length}
                                                                </td>
                                                                <td className="p-3 text-right">
                                                                    <button
                                                                        onClick={async () => {
                                                                            if (confirm(t('confirmDeleteZone') || `Delete zone "${zone.zone}"?`)) {
                                                                                try {
                                                                                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/zones/${zone.zone}`, { method: 'DELETE' });
                                                                                    if (res.ok) {
                                                                                        addToast(t('zoneDeleted') || 'Zone deleted', 'success');
                                                                                        addToast('💡 Click "Apply / Reload" to deploy', 'info');
                                                                                        fetchAllData();
                                                                                    } else {
                                                                                        const err = await res.json();
                                                                                        addToast(err.error || 'Failed to delete zone', 'error');
                                                                                    }
                                                                                } catch (e) {
                                                                                    addToast('Failed to delete zone', 'error');
                                                                                }
                                                                            }
                                                                        }}
                                                                        className="p-1.5 hover:bg-red-500/20 rounded text-red-400"
                                                                        title={t('delete')}
                                                                    >
                                                                        <Icons.Trash2 className="w-4 h-4" />
                                                                    </button>
                                                                </td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            )}
                                        </div>

                                        {/* VNets */}
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                            <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                <h3 className="font-semibold flex items-center gap-2">
                                                    <Icons.Network className="w-5 h-5 text-purple-400" />
                                                    {t('sdnVnets') || 'VNets'}
                                                </h3>
                                                <button 
                                                    onClick={() => { 
                                                        setNewVnet({ vnet: '', zone: sdnData.zones[0]?.zone || '', tag: '', alias: '' }); 
                                                        setShowAddVnet(true); 
                                                    }}
                                                    className="flex items-center gap-2 px-3 py-1.5 bg-purple-600 hover:bg-purple-700 rounded-lg text-sm"
                                                    disabled={sdnData.zones.length === 0}
                                                >
                                                    <Icons.Plus /> {t('add')}
                                                </button>
                                            </div>
                                            {sdnData.vnets.length === 0 ? (
                                                <div className="p-8 text-center text-gray-500">
                                                    <p>{t('noVnets') || 'No VNets configured'}</p>
                                                    {sdnData.zones.length === 0 && (
                                                        <p className="text-sm mt-2">{t('createZoneFirst') || 'Create a zone first'}</p>
                                                    )}
                                                </div>
                                            ) : (
                                                <table className="w-full">
                                                    <thead className="bg-proxmox-dark">
                                                        <tr>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('vnet') || 'VNet'}</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('zone') || 'Zone'}</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('alias') || 'Alias'}</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">VLAN Tag</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('subnets') || 'Subnets'}</th>
                                                            <th className="text-right p-3 text-sm text-gray-400">{t('actions')}</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {sdnData.vnets.map(vnet => {
                                                            const vnetSubnets = sdnData.subnets.filter(s => s.vnet === vnet.vnet);
                                                            return (
                                                                <tr key={vnet.vnet} className="border-t border-proxmox-border hover:bg-proxmox-hover">
                                                                    <td className="p-3">
                                                                        <span className="font-medium text-white flex items-center gap-2">
                                                                            <span className="text-purple-400">🌐</span>
                                                                            {vnet.vnet}
                                                                        </span>
                                                                    </td>
                                                                    <td className="p-3 text-gray-400">{vnet.zone}</td>
                                                                    <td className="p-3 text-gray-400">{vnet.alias || '-'}</td>
                                                                    <td className="p-3">
                                                                        {vnet.tag ? (
                                                                            <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs">{vnet.tag}</span>
                                                                        ) : '-'}
                                                                    </td>
                                                                    <td className="p-3">
                                                                        <div className="flex flex-wrap gap-1">
                                                                            {vnetSubnets.length > 0 ? vnetSubnets.map(s => (
                                                                                <span key={s.subnet || s.cidr} className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">
                                                                                    {s.subnet || s.cidr}
                                                                                </span>
                                                                            )) : (
                                                                                <span className="text-gray-500 text-xs">-</span>
                                                                            )}
                                                                            <button
                                                                                onClick={() => {
                                                                                    setNewSubnet({ subnet: '', gateway: '', snat: 0, dhcp: 'none' });
                                                                                    setShowAddSubnet(vnet.vnet);
                                                                                }}
                                                                                className="px-2 py-0.5 bg-proxmox-dark hover:bg-proxmox-hover border border-proxmox-border rounded text-xs text-gray-400"
                                                                                title={t('addSubnet') || 'Add Subnet'}
                                                                            >
                                                                                +
                                                                            </button>
                                                                        </div>
                                                                    </td>
                                                                    <td className="p-3 text-right">
                                                                        <button
                                                                            onClick={async () => {
                                                                                if (confirm(t('confirmDeleteVnet') || `Delete VNet "${vnet.vnet}"?`)) {
                                                                                    try {
                                                                                        const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/vnets/${vnet.vnet}`, { method: 'DELETE' });
                                                                                        if (res.ok) {
                                                                                            addToast(t('vnetDeleted') || 'VNet deleted', 'success');
                                                                                            addToast('💡 Click "Apply / Reload" to deploy', 'info');
                                                                                            fetchAllData();
                                                                                        } else {
                                                                                            const err = await res.json();
                                                                                            addToast(err.error || 'Failed to delete VNet', 'error');
                                                                                        }
                                                                                    } catch (e) {
                                                                                        addToast('Failed to delete VNet', 'error');
                                                                                    }
                                                                                }
                                                                            }}
                                                                            className="p-1.5 hover:bg-red-500/20 rounded text-red-400"
                                                                            title={t('delete')}
                                                                        >
                                                                            <Icons.Trash2 className="w-4 h-4" />
                                                                        </button>
                                                                    </td>
                                                                </tr>
                                                            );
                                                        })}
                                                    </tbody>
                                                </table>
                                            )}
                                        </div>

                                        {/* SDN Summary Info */}
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4">
                                            <h3 className="font-semibold mb-3 flex items-center gap-2">
                                                <Icons.Info className="w-5 h-5 text-blue-400" />
                                                {t('sdnInfo') || 'SDN Information'}
                                            </h3>
                                            <div className="grid grid-cols-2 md:grid-cols-6 gap-4 text-sm">
                                                <div>
                                                    <span className="text-gray-400">{t('zones') || 'Zones'}:</span>
                                                    <span className="ml-2 font-medium">{sdnData.zones.length}</span>
                                                </div>
                                                <div>
                                                    <span className="text-gray-400">{t('vnets') || 'VNets'}:</span>
                                                    <span className="ml-2 font-medium">{sdnData.vnets.length}</span>
                                                </div>
                                                <div>
                                                    <span className="text-gray-400">{t('subnets') || 'Subnets'}:</span>
                                                    <span className="ml-2 font-medium">{sdnData.subnets.length}</span>
                                                </div>
                                                <div>
                                                    <span className="text-gray-400">{t('controllers') || 'Controllers'}:</span>
                                                    <span className="ml-2 font-medium">{sdnData.controllers.length}</span>
                                                </div>
                                                <div>
                                                    <span className="text-gray-400">IPAM:</span>
                                                    <span className="ml-2 font-medium">{sdnData.ipams?.length || 0}</span>
                                                </div>
                                                <div>
                                                    <span className="text-gray-400">DNS:</span>
                                                    <span className="ml-2 font-medium">{sdnData.dns?.length || 0}</span>
                                                </div>
                                            </div>
                                        </div>

                                        {/* Controllers */}
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                            <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                <h3 className="font-semibold flex items-center gap-2">
                                                    <Icons.Cpu className="w-5 h-5 text-blue-400" />
                                                    {t('controllers') || 'Controllers'}
                                                </h3>
                                                <button 
                                                    onClick={() => { setNewController({ controller: '', type: 'evpn' }); setShowAddController(true); }}
                                                    className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm"
                                                >
                                                    <Icons.Plus /> {t('add')}
                                                </button>
                                            </div>
                                            {sdnData.controllers.length === 0 ? (
                                                <div className="p-6 text-center text-gray-500 text-sm">
                                                    {t('noControllers') || 'No controllers configured. Controllers are needed for EVPN/VXLAN zones.'}
                                                </div>
                                            ) : (
                                                <table className="w-full">
                                                    <thead className="bg-proxmox-dark">
                                                        <tr>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('name') || 'Name'}</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('type') || 'Type'}</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">ASN</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">Peers</th>
                                                            <th className="text-right p-3 text-sm text-gray-400">{t('actions')}</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {sdnData.controllers.map(ctrl => (
                                                            <tr key={ctrl.controller} className="border-t border-proxmox-border hover:bg-proxmox-hover">
                                                                <td className="p-3 font-medium text-white">{ctrl.controller}</td>
                                                                <td className="p-3">
                                                                    <span className={`px-2 py-1 rounded text-xs ${
                                                                        ctrl.type === 'evpn' ? 'bg-purple-500/20 text-purple-400' :
                                                                        ctrl.type === 'bgp' ? 'bg-blue-500/20 text-blue-400' :
                                                                        ctrl.type === 'isis' ? 'bg-orange-500/20 text-orange-400' :
                                                                        'bg-gray-500/20 text-gray-400'
                                                                    }`}>
                                                                        {ctrl.type?.toUpperCase()}
                                                                    </span>
                                                                </td>
                                                                <td className="p-3 text-gray-400">{ctrl.asn || '-'}</td>
                                                                <td className="p-3 text-gray-400">{ctrl.peers || '-'}</td>
                                                                <td className="p-3 text-right">
                                                                    <button
                                                                        onClick={async () => {
                                                                            if (confirm(`Delete controller "${ctrl.controller}"?`)) {
                                                                                try {
                                                                                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/controllers/${ctrl.controller}`, { method: 'DELETE' });
                                                                                    if (res.ok) {
                                                                                        addToast('Controller deleted - Click Apply to activate', 'success');
                                                                                        addToast('💡 Click "Apply / Reload" to deploy', 'info');
                                                                                        fetchAllData();
                                                                                    } else {
                                                                                        const err = await res.json();
                                                                                        addToast(err.error || 'Failed', 'error');
                                                                                    }
                                                                                } catch (e) { addToast('Failed', 'error'); }
                                                                            }
                                                                        }}
                                                                        className="p-1.5 hover:bg-red-500/20 rounded text-red-400"
                                                                    >
                                                                        <Icons.Trash2 className="w-4 h-4" />
                                                                    </button>
                                                                </td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            )}
                                        </div>

                                        {/* IPAM */}
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                            <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                <h3 className="font-semibold flex items-center gap-2">
                                                    <Icons.Database className="w-5 h-5 text-green-400" />
                                                    IPAM
                                                </h3>
                                                <button 
                                                    onClick={() => { setNewIpam({ ipam: '', type: 'pve' }); setShowAddIpam(true); }}
                                                    className="flex items-center gap-2 px-3 py-1.5 bg-green-600 hover:bg-green-700 rounded-lg text-sm"
                                                >
                                                    <Icons.Plus /> {t('add')}
                                                </button>
                                            </div>
                                            {(sdnData.ipams?.length || 0) === 0 ? (
                                                <div className="p-6 text-center text-gray-500 text-sm">
                                                    {t('noIpam') || 'No IPAM configured. IPAM provides IP address management for subnets.'}
                                                </div>
                                            ) : (
                                                <table className="w-full">
                                                    <thead className="bg-proxmox-dark">
                                                        <tr>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('name') || 'Name'}</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('type') || 'Type'}</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">URL</th>
                                                            <th className="text-right p-3 text-sm text-gray-400">{t('actions')}</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {sdnData.ipams?.map(ipam => (
                                                            <tr key={ipam.ipam} className="border-t border-proxmox-border hover:bg-proxmox-hover">
                                                                <td className="p-3 font-medium text-white">{ipam.ipam}</td>
                                                                <td className="p-3">
                                                                    <span className={`px-2 py-1 rounded text-xs ${
                                                                        ipam.type === 'pve' ? 'bg-orange-500/20 text-orange-400' :
                                                                        ipam.type === 'netbox' ? 'bg-blue-500/20 text-blue-400' :
                                                                        ipam.type === 'phpipam' ? 'bg-purple-500/20 text-purple-400' :
                                                                        'bg-gray-500/20 text-gray-400'
                                                                    }`}>
                                                                        {ipam.type}
                                                                    </span>
                                                                </td>
                                                                <td className="p-3 text-gray-400">{ipam.url || '-'}</td>
                                                                <td className="p-3 text-right">
                                                                    <button
                                                                        onClick={async () => {
                                                                            if (confirm(`Delete IPAM "${ipam.ipam}"?`)) {
                                                                                try {
                                                                                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/ipams/${ipam.ipam}`, { method: 'DELETE' });
                                                                                    if (res.ok) {
                                                                                        addToast('IPAM deleted - Click Apply to activate', 'success');
                                                                                        addToast('💡 Click "Apply / Reload" to deploy', 'info');
                                                                                        fetchAllData();
                                                                                    } else {
                                                                                        const err = await res.json();
                                                                                        addToast(err.error || 'Failed', 'error');
                                                                                    }
                                                                                } catch (e) { addToast('Failed', 'error'); }
                                                                            }
                                                                        }}
                                                                        className="p-1.5 hover:bg-red-500/20 rounded text-red-400"
                                                                    >
                                                                        <Icons.Trash2 className="w-4 h-4" />
                                                                    </button>
                                                                </td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            )}
                                        </div>

                                        {/* DNS */}
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                            <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                <h3 className="font-semibold flex items-center gap-2">
                                                    <Icons.Globe className="w-5 h-5 text-cyan-400" />
                                                    DNS
                                                </h3>
                                                <button 
                                                    onClick={() => { setNewDns({ dns: '', type: 'powerdns', url: '', key: '', reversev6mask: 64 }); setShowAddDns(true); }}
                                                    className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 rounded-lg text-sm"
                                                >
                                                    <Icons.Plus /> {t('add')}
                                                </button>
                                            </div>
                                            {(sdnData.dns?.length || 0) === 0 ? (
                                                <div className="p-6 text-center text-gray-500 text-sm">
                                                    {t('noDns') || 'No DNS configured. DNS integration enables automatic DNS registration for VMs.'}
                                                </div>
                                            ) : (
                                                <table className="w-full">
                                                    <thead className="bg-proxmox-dark">
                                                        <tr>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('name') || 'Name'}</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">{t('type') || 'Type'}</th>
                                                            <th className="text-left p-3 text-sm text-gray-400">URL</th>
                                                            <th className="text-right p-3 text-sm text-gray-400">{t('actions')}</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {sdnData.dns?.map(dns => (
                                                            <tr key={dns.dns} className="border-t border-proxmox-border hover:bg-proxmox-hover">
                                                                <td className="p-3 font-medium text-white">{dns.dns}</td>
                                                                <td className="p-3">
                                                                    <span className="px-2 py-1 rounded text-xs bg-cyan-500/20 text-cyan-400">
                                                                        {dns.type}
                                                                    </span>
                                                                </td>
                                                                <td className="p-3 text-gray-400">{dns.url || '-'}</td>
                                                                <td className="p-3 text-right">
                                                                    <button
                                                                        onClick={async () => {
                                                                            if (confirm(`Delete DNS "${dns.dns}"?`)) {
                                                                                try {
                                                                                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/dns/${dns.dns}`, { method: 'DELETE' });
                                                                                    if (res.ok) {
                                                                                        addToast('DNS deleted - Click Apply to activate', 'success');
                                                                                        addToast('💡 Click "Apply / Reload" to deploy', 'info');
                                                                                        fetchAllData();
                                                                                    } else {
                                                                                        const err = await res.json();
                                                                                        addToast(err.error || 'Failed', 'error');
                                                                                    }
                                                                                } catch (e) { addToast('Failed', 'error'); }
                                                                            }
                                                                        }}
                                                                        className="p-1.5 hover:bg-red-500/20 rounded text-red-400"
                                                                    >
                                                                        <Icons.Trash2 className="w-4 h-4" />
                                                                    </button>
                                                                </td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            )}
                                        </div>
                                    </>
                                )}

                                {/* Add Zone Modal */}
                                {showAddZone && (
                                    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
                                            <h3 className="text-lg font-semibold mb-4">{t('addZone') || 'Add Zone'}</h3>
                                            <div className="space-y-4">
                                                {/* Basic Settings */}
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('zoneName') || 'Zone Name'} *</label>
                                                        <input
                                                            type="text"
                                                            value={newZone.zone}
                                                            onChange={e => setNewZone({...newZone, zone: e.target.value})}
                                                            placeholder="myzone"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('type') || 'Type'} *</label>
                                                        <select
                                                            value={newZone.type}
                                                            onChange={e => setNewZone({...newZone, type: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="simple">Simple</option>
                                                            <option value="vlan">VLAN</option>
                                                            <option value="qinq">QinQ</option>
                                                            <option value="vxlan">VXLAN</option>
                                                            <option value="evpn">EVPN</option>
                                                        </select>
                                                    </div>
                                                </div>
                                                <p className="text-xs text-gray-500 -mt-2">
                                                    {newZone.type === 'simple' && (t('simpleZoneDesc') || 'Isolated zone with simple bridging - each node has its own bridge')}
                                                    {newZone.type === 'vlan' && (t('vlanZoneDesc') || 'VLAN-based zone using 802.1q tagging on a shared bridge')}
                                                    {newZone.type === 'qinq' && 'QinQ (802.1ad) - VLAN stacking for service provider networks'}
                                                    {newZone.type === 'vxlan' && (t('vxlanZoneDesc') || 'VXLAN overlay network - Layer 2 over Layer 3 using UDP encapsulation')}
                                                    {newZone.type === 'evpn' && (t('evpnZoneDesc') || 'BGP EVPN with VXLAN - advanced datacenter fabric with BGP control plane')}
                                                </p>

                                                {/* Bridge (for VLAN/QinQ) */}
                                                {(newZone.type === 'vlan' || newZone.type === 'qinq') && (
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Bridge *</label>
                                                        <input
                                                            type="text"
                                                            value={newZone.bridge || ''}
                                                            onChange={e => setNewZone({...newZone, bridge: e.target.value})}
                                                            placeholder="vmbr0"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                        <p className="text-xs text-gray-500 mt-1">Physical bridge to use for VLAN tagging</p>
                                                    </div>
                                                )}

                                                {/* VXLAN/EVPN specific */}
                                                {(newZone.type === 'vxlan' || newZone.type === 'evpn') && (
                                                    <>
                                                        <div className="grid grid-cols-2 gap-4">
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-1">Peers (multicast/unicast)</label>
                                                                <input
                                                                    type="text"
                                                                    value={newZone.peers || ''}
                                                                    onChange={e => setNewZone({...newZone, peers: e.target.value})}
                                                                    placeholder="10.0.0.1,10.0.0.2"
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                />
                                                            </div>
                                                            {newZone.type === 'evpn' && (
                                                                <div>
                                                                    <label className="block text-sm text-gray-400 mb-1">Controller</label>
                                                                    <select
                                                                        value={newZone.controller || ''}
                                                                        onChange={e => setNewZone({...newZone, controller: e.target.value})}
                                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                    >
                                                                        <option value="">-- Select --</option>
                                                                        {sdnData.controllers.map(c => (
                                                                            <option key={c.controller} value={c.controller}>{c.controller} ({c.type})</option>
                                                                        ))}
                                                                    </select>
                                                                </div>
                                                            )}
                                                        </div>
                                                        {newZone.type === 'evpn' && (
                                                            <div className="grid grid-cols-2 gap-4">
                                                                <div>
                                                                    <label className="block text-sm text-gray-400 mb-1">VRF VXLAN ID</label>
                                                                    <input
                                                                        type="number"
                                                                        value={newZone['vrf-vxlan'] || ''}
                                                                        onChange={e => setNewZone({...newZone, 'vrf-vxlan': e.target.value})}
                                                                        placeholder="Auto"
                                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-sm text-gray-400 mb-1">Exit Nodes</label>
                                                                    <input
                                                                        type="text"
                                                                        value={newZone['exitnodes'] || ''}
                                                                        onChange={e => setNewZone({...newZone, 'exitnodes': e.target.value})}
                                                                        placeholder="node1,node2"
                                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                    />
                                                                </div>
                                                            </div>
                                                        )}
                                                    </>
                                                )}

                                                {/* Common options */}
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">MTU</label>
                                                        <input
                                                            type="number"
                                                            value={newZone.mtu || ''}
                                                            onChange={e => setNewZone({...newZone, mtu: e.target.value})}
                                                            placeholder="auto"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Nodes</label>
                                                        <input
                                                            type="text"
                                                            value={newZone.nodes || ''}
                                                            onChange={e => setNewZone({...newZone, nodes: e.target.value})}
                                                            placeholder="all (or: node1,node2)"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                </div>

                                                {/* IPAM & DNS */}
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">IPAM</label>
                                                        <select
                                                            value={newZone.ipam || ''}
                                                            onChange={e => setNewZone({...newZone, ipam: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="">-- None --</option>
                                                            {sdnData.ipams?.map(i => (
                                                                <option key={i.ipam} value={i.ipam}>{i.ipam} ({i.type})</option>
                                                            ))}
                                                        </select>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">DNS Server</label>
                                                        <select
                                                            value={newZone.dns || ''}
                                                            onChange={e => setNewZone({...newZone, dns: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="">-- None --</option>
                                                            {sdnData.dns?.map(d => (
                                                                <option key={d.dns} value={d.dns}>{d.dns} ({d.type})</option>
                                                            ))}
                                                        </select>
                                                    </div>
                                                </div>

                                                {newZone.dns && (
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">DNS Zone</label>
                                                            <input
                                                                type="text"
                                                                value={newZone.dnszone || ''}
                                                                onChange={e => setNewZone({...newZone, dnszone: e.target.value})}
                                                                placeholder="example.com"
                                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                            />
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Reverse DNS Zone</label>
                                                            <input
                                                                type="text"
                                                                value={newZone.reversedns || ''}
                                                                onChange={e => setNewZone({...newZone, reversedns: e.target.value})}
                                                                placeholder="10.in-addr.arpa"
                                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                            />
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                            <div className="flex justify-end gap-3 mt-6">
                                                <button
                                                    onClick={() => setShowAddZone(false)}
                                                    className="px-4 py-2 bg-proxmox-border hover:bg-proxmox-hover rounded-lg"
                                                >
                                                    {t('cancel')}
                                                </button>
                                                <button
                                                    onClick={async () => {
                                                        if (!newZone.zone) {
                                                            addToast(t('zoneNameRequired') || 'Zone name is required', 'error');
                                                            return;
                                                        }
                                                        if ((newZone.type === 'vlan' || newZone.type === 'qinq') && !newZone.bridge) {
                                                            addToast('Bridge is required for VLAN/QinQ zones', 'error');
                                                            return;
                                                        }
                                                        try {
                                                            // Build payload with only non-empty values
                                                            const payload = { zone: newZone.zone, type: newZone.type };
                                                            ['bridge', 'mtu', 'nodes', 'ipam', 'dns', 'dnszone', 'reversedns', 'peers', 'controller', 'vrf-vxlan', 'exitnodes'].forEach(key => {
                                                                if (newZone[key]) payload[key] = newZone[key];
                                                            });
                                                            if (payload.mtu) payload.mtu = parseInt(payload.mtu);
                                                            
                                                            const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/zones`, {
                                                                method: 'POST',
                                                                headers: { 'Content-Type': 'application/json' },
                                                                body: JSON.stringify(payload)
                                                            });
                                                            if (res.ok) {
                                                                addToast(t('zoneCreated') || 'Zone created', 'success');
                                                                addToast(t('sdnApplyReminder') || '💡 Remember to click "Apply / Reload" to deploy changes', 'info');
                                                                setShowAddZone(false);
                                                                setNewZone({ zone: '', type: 'simple', bridge: '', mtu: '', nodes: '', ipam: '', dns: '', dnszone: '', reversedns: '' });
                                                                fetchAllData();
                                                            } else {
                                                                const err = await res.json();
                                                                addToast(err.error || 'Failed to create zone', 'error');
                                                            }
                                                        } catch (e) {
                                                            addToast('Failed to create zone', 'error');
                                                        }
                                                    }}
                                                    className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg"
                                                >
                                                    {t('create')}
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Add VNet Modal */}
                                {showAddVnet && (
                                    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-md p-6">
                                            <h3 className="text-lg font-semibold mb-4">{t('addVnet') || 'Add VNet'}</h3>
                                            <div className="space-y-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('vnetName') || 'VNet Name'}</label>
                                                    <input
                                                        type="text"
                                                        value={newVnet.vnet}
                                                        onChange={e => setNewVnet({...newVnet, vnet: e.target.value})}
                                                        placeholder="myvnet"
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('zone') || 'Zone'}</label>
                                                    <select
                                                        value={newVnet.zone}
                                                        onChange={e => setNewVnet({...newVnet, zone: e.target.value})}
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                    >
                                                        {sdnData.zones.map(z => (
                                                            <option key={z.zone} value={z.zone}>{z.zone} ({z.type})</option>
                                                        ))}
                                                    </select>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">{t('alias') || 'Alias'} ({t('optional')})</label>
                                                    <input
                                                        type="text"
                                                        value={newVnet.alias}
                                                        onChange={e => setNewVnet({...newVnet, alias: e.target.value})}
                                                        placeholder="My Network"
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">VLAN Tag ({t('optional')})</label>
                                                    <input
                                                        type="number"
                                                        value={newVnet.tag}
                                                        onChange={e => setNewVnet({...newVnet, tag: e.target.value})}
                                                        placeholder="100"
                                                        min="1"
                                                        max="4094"
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                    />
                                                </div>
                                            </div>
                                            <div className="flex justify-end gap-3 mt-6">
                                                <button
                                                    onClick={() => setShowAddVnet(false)}
                                                    className="px-4 py-2 bg-proxmox-border hover:bg-proxmox-hover rounded-lg"
                                                >
                                                    {t('cancel')}
                                                </button>
                                                <button
                                                    onClick={async () => {
                                                        if (!newVnet.vnet || !newVnet.zone) {
                                                            addToast(t('vnetNameZoneRequired') || 'VNet name and zone are required', 'error');
                                                            return;
                                                        }
                                                        try {
                                                            const payload = { vnet: newVnet.vnet, zone: newVnet.zone };
                                                            if (newVnet.alias) payload.alias = newVnet.alias;
                                                            if (newVnet.tag) payload.tag = parseInt(newVnet.tag);
                                                            
                                                            const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/vnets`, {
                                                                method: 'POST',
                                                                headers: { 'Content-Type': 'application/json' },
                                                                body: JSON.stringify(payload)
                                                            });
                                                            if (res.ok) {
                                                                addToast(t('vnetCreated') || 'VNet created', 'success');
                                                                addToast(t('sdnApplyReminder') || '💡 Click "Apply / Reload" to deploy', 'info');
                                                                setShowAddVnet(false);
                                                                fetchAllData();
                                                            } else {
                                                                const err = await res.json();
                                                                addToast(err.error || 'Failed to create VNet', 'error');
                                                            }
                                                        } catch (e) {
                                                            addToast('Failed to create VNet', 'error');
                                                        }
                                                    }}
                                                    className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg"
                                                >
                                                    {t('create')}
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Add Subnet Modal */}
                                {showAddSubnet && (
                                    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-lg p-6">
                                            <h3 className="text-lg font-semibold mb-4">{t('addSubnet') || 'Add Subnet'} - {showAddSubnet}</h3>
                                            <div className="space-y-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Subnet (CIDR) *</label>
                                                    <input
                                                        type="text"
                                                        value={newSubnet.subnet}
                                                        onChange={e => setNewSubnet({...newSubnet, subnet: e.target.value})}
                                                        placeholder="10.0.0.0/24"
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                    />
                                                </div>
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('gateway') || 'Gateway'}</label>
                                                        <input
                                                            type="text"
                                                            value={newSubnet.gateway}
                                                            onChange={e => setNewSubnet({...newSubnet, gateway: e.target.value})}
                                                            placeholder="10.0.0.1"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">DNS Server</label>
                                                        <input
                                                            type="text"
                                                            value={newSubnet.dnszoneprefix || ''}
                                                            onChange={e => setNewSubnet({...newSubnet, dnszoneprefix: e.target.value})}
                                                            placeholder="10.0.0.1"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">DHCP Range</label>
                                                    <input
                                                        type="text"
                                                        value={newSubnet['dhcp-range'] || ''}
                                                        onChange={e => setNewSubnet({...newSubnet, 'dhcp-range': e.target.value})}
                                                        placeholder="start-address=10.0.0.100,end-address=10.0.0.200"
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                    />
                                                    <p className="text-xs text-gray-500 mt-1">Format: start-address=IP,end-address=IP</p>
                                                </div>
                                                <div className="flex flex-wrap gap-4">
                                                    <label className="flex items-center gap-2 cursor-pointer">
                                                        <input
                                                            type="checkbox"
                                                            checked={newSubnet.snat === 1}
                                                            onChange={e => setNewSubnet({...newSubnet, snat: e.target.checked ? 1 : 0})}
                                                            className="w-4 h-4 rounded"
                                                        />
                                                        <span className="text-sm">SNAT ({t('sourceNat') || 'Source NAT'})</span>
                                                    </label>
                                                </div>
                                            </div>
                                            <div className="flex justify-end gap-3 mt-6">
                                                <button
                                                    onClick={() => setShowAddSubnet(null)}
                                                    className="px-4 py-2 bg-proxmox-border hover:bg-proxmox-hover rounded-lg"
                                                >
                                                    {t('cancel')}
                                                </button>
                                                <button
                                                    onClick={async () => {
                                                        if (!newSubnet.subnet) {
                                                            addToast(t('subnetRequired') || 'Subnet is required', 'error');
                                                            return;
                                                        }
                                                        try {
                                                            const payload = { subnet: newSubnet.subnet };
                                                            if (newSubnet.gateway) payload.gateway = newSubnet.gateway;
                                                            if (newSubnet.snat) payload.snat = 1;
                                                            if (newSubnet['dhcp-range']) payload['dhcp-range'] = newSubnet['dhcp-range'];
                                                            if (newSubnet.dnszoneprefix) payload.dnszoneprefix = newSubnet.dnszoneprefix;
                                                            
                                                            const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/vnets/${showAddSubnet}/subnets`, {
                                                                method: 'POST',
                                                                headers: { 'Content-Type': 'application/json' },
                                                                body: JSON.stringify(payload)
                                                            });
                                                            if (res.ok) {
                                                                addToast(t('subnetCreated') || 'Subnet created', 'success');
                                                                addToast(t('sdnApplyReminder') || '💡 Click "Apply / Reload" to deploy', 'info');
                                                                setShowAddSubnet(null);
                                                                setNewSubnet({ subnet: '', gateway: '', snat: 0, dhcp: 'none', 'dhcp-range': '' });
                                                                fetchAllData();
                                                            } else {
                                                                const err = await res.json();
                                                                addToast(err.error || 'Failed to create subnet', 'error');
                                                            }
                                                        } catch (e) {
                                                            addToast('Failed to create subnet', 'error');
                                                        }
                                                    }}
                                                    className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg"
                                                >
                                                    {t('create')}
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Add Controller Modal */}
                                {showAddController && (
                                    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-lg p-6">
                                            <h3 className="text-lg font-semibold mb-4">{t('addController') || 'Add Controller'}</h3>
                                            <div className="space-y-4">
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('name') || 'Name'}</label>
                                                        <input
                                                            type="text"
                                                            value={newController.controller}
                                                            onChange={e => setNewController({...newController, controller: e.target.value})}
                                                            placeholder="mycontroller"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('type') || 'Type'}</label>
                                                        <select
                                                            value={newController.type}
                                                            onChange={e => setNewController({...newController, type: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="evpn">EVPN</option>
                                                            <option value="bgp">BGP</option>
                                                            <option value="isis">ISIS</option>
                                                        </select>
                                                    </div>
                                                </div>
                                                {(newController.type === 'evpn' || newController.type === 'bgp') && (
                                                    <>
                                                        <div className="grid grid-cols-2 gap-4">
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-1">ASN</label>
                                                                <input
                                                                    type="number"
                                                                    value={newController.asn}
                                                                    onChange={e => setNewController({...newController, asn: e.target.value})}
                                                                    placeholder="65000"
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                />
                                                            </div>
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-1">Peers</label>
                                                                <input
                                                                    type="text"
                                                                    value={newController.peers}
                                                                    onChange={e => setNewController({...newController, peers: e.target.value})}
                                                                    placeholder="10.0.0.1,10.0.0.2"
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                />
                                                            </div>
                                                        </div>
                                                        <div className="flex flex-wrap gap-4">
                                                            <label className="flex items-center gap-2 cursor-pointer">
                                                                <input
                                                                    type="checkbox"
                                                                    checked={newController.ebgp === 1}
                                                                    onChange={e => setNewController({...newController, ebgp: e.target.checked ? 1 : 0})}
                                                                    className="w-4 h-4 rounded"
                                                                />
                                                                <span className="text-sm">eBGP</span>
                                                            </label>
                                                            <label className="flex items-center gap-2 cursor-pointer">
                                                                <input
                                                                    type="checkbox"
                                                                    checked={newController['ebgp-multihop'] === 1}
                                                                    onChange={e => setNewController({...newController, 'ebgp-multihop': e.target.checked ? 1 : 0})}
                                                                    className="w-4 h-4 rounded"
                                                                />
                                                                <span className="text-sm">eBGP Multihop</span>
                                                            </label>
                                                            <label className="flex items-center gap-2 cursor-pointer">
                                                                <input
                                                                    type="checkbox"
                                                                    checked={newController['bgp-multipath-as-path-relax'] === 1}
                                                                    onChange={e => setNewController({...newController, 'bgp-multipath-as-path-relax': e.target.checked ? 1 : 0})}
                                                                    className="w-4 h-4 rounded"
                                                                />
                                                                <span className="text-sm">Multipath AS-Path Relax</span>
                                                            </label>
                                                        </div>
                                                    </>
                                                )}
                                                {newController.type === 'isis' && (
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">ISIS Domain</label>
                                                        <input
                                                            type="text"
                                                            value={newController['isis-domain'] || ''}
                                                            onChange={e => setNewController({...newController, 'isis-domain': e.target.value})}
                                                            placeholder="49.0001"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                )}
                                            </div>
                                            <div className="flex justify-end gap-3 mt-6">
                                                <button onClick={() => setShowAddController(false)} className="px-4 py-2 bg-proxmox-border hover:bg-proxmox-hover rounded-lg">
                                                    {t('cancel')}
                                                </button>
                                                <button
                                                    onClick={async () => {
                                                        if (!newController.controller) {
                                                            addToast('Controller name is required', 'error');
                                                            return;
                                                        }
                                                        try {
                                                            const payload = { controller: newController.controller, type: newController.type };
                                                            if (newController.asn) payload.asn = parseInt(newController.asn);
                                                            if (newController.peers) payload.peers = newController.peers;
                                                            if (newController.ebgp) payload.ebgp = 1;
                                                            if (newController['ebgp-multihop']) payload['ebgp-multihop'] = 1;
                                                            if (newController['bgp-multipath-as-path-relax']) payload['bgp-multipath-as-path-relax'] = 1;
                                                            if (newController['isis-domain']) payload['isis-domain'] = newController['isis-domain'];
                                                            
                                                            const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/controllers`, {
                                                                method: 'POST',
                                                                headers: { 'Content-Type': 'application/json' },
                                                                body: JSON.stringify(payload)
                                                            });
                                                            if (res.ok) {
                                                                addToast('Controller created - Click Apply to activate', 'success');
                                                                addToast('💡 Click "Apply / Reload" to deploy', 'info');
                                                                setShowAddController(false);
                                                                fetchAllData();
                                                            } else {
                                                                const err = await res.json();
                                                                addToast(err.error || 'Failed', 'error');
                                                            }
                                                        } catch (e) { addToast('Failed to create controller', 'error'); }
                                                    }}
                                                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg"
                                                >
                                                    {t('create')}
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Add IPAM Modal */}
                                {showAddIpam && (
                                    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-lg p-6">
                                            <h3 className="text-lg font-semibold mb-4">{t('addIpam') || 'Add IPAM'}</h3>
                                            <div className="space-y-4">
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('name') || 'Name'}</label>
                                                        <input
                                                            type="text"
                                                            value={newIpam.ipam}
                                                            onChange={e => setNewIpam({...newIpam, ipam: e.target.value})}
                                                            placeholder="myipam"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('type') || 'Type'}</label>
                                                        <select
                                                            value={newIpam.type}
                                                            onChange={e => setNewIpam({...newIpam, type: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="pve">PVE (built-in)</option>
                                                            <option value="netbox">Netbox</option>
                                                            <option value="phpipam">phpIPAM</option>
                                                        </select>
                                                    </div>
                                                </div>
                                                {newIpam.type !== 'pve' && (
                                                    <>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">URL</label>
                                                            <input
                                                                type="text"
                                                                value={newIpam.url}
                                                                onChange={e => setNewIpam({...newIpam, url: e.target.value})}
                                                                placeholder="https://netbox.example.com/api"
                                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                            />
                                                        </div>
                                                        <div>
                                                            <label className="block text-sm text-gray-400 mb-1">Token / API Key</label>
                                                            <input
                                                                type="password"
                                                                value={newIpam.token}
                                                                onChange={e => setNewIpam({...newIpam, token: e.target.value})}
                                                                placeholder="API token"
                                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                            />
                                                        </div>
                                                        {newIpam.type === 'phpipam' && (
                                                            <div>
                                                                <label className="block text-sm text-gray-400 mb-1">Section</label>
                                                                <input
                                                                    type="number"
                                                                    value={newIpam.section}
                                                                    onChange={e => setNewIpam({...newIpam, section: e.target.value})}
                                                                    placeholder="1"
                                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                                />
                                                            </div>
                                                        )}
                                                    </>
                                                )}
                                                <p className="text-xs text-gray-500">
                                                    {newIpam.type === 'pve' && 'Built-in PVE IPAM stores IP assignments locally in the cluster.'}
                                                    {newIpam.type === 'netbox' && 'Netbox is an open source IPAM and DCIM tool.'}
                                                    {newIpam.type === 'phpipam' && 'phpIPAM is an open source IP address management application.'}
                                                </p>
                                            </div>
                                            <div className="flex justify-end gap-3 mt-6">
                                                <button onClick={() => setShowAddIpam(false)} className="px-4 py-2 bg-proxmox-border hover:bg-proxmox-hover rounded-lg">
                                                    {t('cancel')}
                                                </button>
                                                <button
                                                    onClick={async () => {
                                                        if (!newIpam.ipam) {
                                                            addToast('IPAM name is required', 'error');
                                                            return;
                                                        }
                                                        try {
                                                            const payload = { ipam: newIpam.ipam, type: newIpam.type };
                                                            if (newIpam.url) payload.url = newIpam.url;
                                                            if (newIpam.token) payload.token = newIpam.token;
                                                            if (newIpam.section) payload.section = parseInt(newIpam.section);
                                                            
                                                            const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/ipams`, {
                                                                method: 'POST',
                                                                headers: { 'Content-Type': 'application/json' },
                                                                body: JSON.stringify(payload)
                                                            });
                                                            if (res.ok) {
                                                                addToast('IPAM created - Click Apply to activate', 'success');
                                                                addToast('💡 Click "Apply / Reload" to deploy', 'info');
                                                                setShowAddIpam(false);
                                                                fetchAllData();
                                                            } else {
                                                                const err = await res.json();
                                                                addToast(err.error || 'Failed', 'error');
                                                            }
                                                        } catch (e) { addToast('Failed to create IPAM', 'error'); }
                                                    }}
                                                    className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg"
                                                >
                                                    {t('create')}
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Add DNS Modal */}
                                {showAddDns && (
                                    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-lg p-6">
                                            <h3 className="text-lg font-semibold mb-4">{t('addDns') || 'Add DNS'}</h3>
                                            <div className="space-y-4">
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('name') || 'Name'}</label>
                                                        <input
                                                            type="text"
                                                            value={newDns.dns}
                                                            onChange={e => setNewDns({...newDns, dns: e.target.value})}
                                                            placeholder="mydns"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('type') || 'Type'}</label>
                                                        <select
                                                            value={newDns.type}
                                                            onChange={e => setNewDns({...newDns, type: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="powerdns">PowerDNS</option>
                                                        </select>
                                                    </div>
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">URL</label>
                                                    <input
                                                        type="text"
                                                        value={newDns.url}
                                                        onChange={e => setNewDns({...newDns, url: e.target.value})}
                                                        placeholder="http://powerdns.example.com:8081/api/v1/servers/localhost"
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">API Key</label>
                                                    <input
                                                        type="password"
                                                        value={newDns.key}
                                                        onChange={e => setNewDns({...newDns, key: e.target.value})}
                                                        placeholder="PowerDNS API key"
                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                    />
                                                </div>
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">TTL ({t('seconds')})</label>
                                                        <input
                                                            type="number"
                                                            value={newDns.ttl}
                                                            onChange={e => setNewDns({...newDns, ttl: e.target.value})}
                                                            placeholder="3600"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Reverse IPv6 Mask</label>
                                                        <input
                                                            type="number"
                                                            value={newDns.reversemaskv6}
                                                            onChange={e => setNewDns({...newDns, reversemaskv6: e.target.value})}
                                                            placeholder="64"
                                                            min="1"
                                                            max="128"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                </div>
                                                <p className="text-xs text-gray-500">
                                                    PowerDNS integration enables automatic DNS registration for VMs with static IPs.
                                                </p>
                                            </div>
                                            <div className="flex justify-end gap-3 mt-6">
                                                <button onClick={() => setShowAddDns(false)} className="px-4 py-2 bg-proxmox-border hover:bg-proxmox-hover rounded-lg">
                                                    {t('cancel')}
                                                </button>
                                                <button
                                                    onClick={async () => {
                                                        if (!newDns.dns || !newDns.url || !newDns.key) {
                                                            addToast('DNS name, URL and API key are required', 'error');
                                                            return;
                                                        }
                                                        try {
                                                            const payload = { 
                                                                dns: newDns.dns, 
                                                                type: newDns.type,
                                                                url: newDns.url,
                                                                key: newDns.key
                                                            };
                                                            if (newDns.ttl) payload.ttl = parseInt(newDns.ttl);
                                                            if (newDns.reversemaskv6) payload.reversemaskv6 = parseInt(newDns.reversemaskv6);
                                                            
                                                            const res = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/sdn/dns`, {
                                                                method: 'POST',
                                                                headers: { 'Content-Type': 'application/json' },
                                                                body: JSON.stringify(payload)
                                                            });
                                                            if (res.ok) {
                                                                addToast('DNS created - Click Apply to activate', 'success');
                                                                addToast('💡 Click "Apply / Reload" to deploy', 'info');
                                                                setShowAddDns(false);
                                                                fetchAllData();
                                                            } else {
                                                                const err = await res.json();
                                                                addToast(err.error || 'Failed', 'error');
                                                            }
                                                        } catch (e) { addToast('Failed to create DNS', 'error'); }
                                                    }}
                                                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 rounded-lg"
                                                >
                                                    {t('create')}
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Backup */}
                        {activeSection === 'backup' && (
                            <div className="space-y-4">
                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                    <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                        <h3 className="font-semibold">{t('backupJobs')}</h3>
                                        <button 
                                            onClick={() => setShowAddBackupJob(true)}
                                            className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                        >
                                            <Icons.Plus /> {t('add')}
                                        </button>
                                    </div>
                                    <table className="w-full">
                                        <thead className="bg-proxmox-dark">
                                            <tr>
                                                <th className="text-left p-3 text-sm text-gray-400">{t('enabled')}</th>
                                                <th className="text-left p-3 text-sm text-gray-400">Node</th>
                                                <th className="text-left p-3 text-sm text-gray-400">{t('schedule')}</th>
                                                <th className="text-left p-3 text-sm text-gray-400">Storage</th>
                                                <th className="text-left p-3 text-sm text-gray-400">Mode</th>
                                                <th className="text-left p-3 text-sm text-gray-400">VMs</th>
                                                <th className="text-left p-3 text-sm text-gray-400"></th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {backupJobs.length === 0 ? (
                                                <tr><td colSpan="7" className="p-8 text-center text-gray-500">{t('noBackupJobs')}</td></tr>
                                            ) : backupJobs.map((job, idx) => (
                                                <tr key={job.id || idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                    <td className="p-3">{job.enabled !== 0 ? <span className="text-green-400">✓</span> : <span className="text-gray-500">✗</span>}</td>
                                                    <td className="p-3">{job.node || t('all')}</td>
                                                    <td className="p-3 font-mono text-sm">{job.schedule || '-'}</td>
                                                    <td className="p-3">{job.storage || '-'}</td>
                                                    <td className="p-3">
                                                        <span className={`px-2 py-0.5 rounded text-xs ${
                                                            job.mode === 'snapshot' ? 'bg-green-500/20 text-green-400' :
                                                            job.mode === 'suspend' ? 'bg-yellow-500/20 text-yellow-400' :
                                                            'bg-blue-500/20 text-blue-400'
                                                        }`}>
                                                            {job.mode || 'snapshot'}
                                                        </span>
                                                    </td>
                                                    <td className="p-3 text-sm">{job.vmid || t('all')}</td>
                                                    <td className="p-3">
                                                        <button onClick={() => deleteBackupJob(job.id)} className="p-1 hover:bg-red-500/20 rounded text-red-400"><Icons.Trash /></button>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>

                                {/* Add Backup Job Modal */}
                                {showAddBackupJob && (
                                    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70" onClick={() => setShowAddBackupJob(false)}>
                                        <div className="w-full max-w-2xl bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden" onClick={e => e.stopPropagation()}>
                                            <div className="p-4 border-b border-proxmox-border bg-proxmox-dark">
                                                <h3 className="font-semibold text-white flex items-center gap-2">
                                                    <Icons.Clock />
                                                    {t('createBackupJob') || 'Create Backup Job'}
                                                </h3>
                                            </div>
                                            <div className="p-6 space-y-4">
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Storage *</label>
                                                        <select
                                                            value={newBackupJob.storage}
                                                            onChange={e => setNewBackupJob({...newBackupJob, storage: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="">{t('selectStorage') || 'Select Storage'}</option>
                                                            {(storage || []).filter(s => s.content?.includes('backup')).map(s => (
                                                                <option key={s.storage} value={s.storage}>{s.storage}</option>
                                                            ))}
                                                        </select>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('schedule')}</label>
                                                        <select
                                                            value={['hourly', 'daily', 'weekly', 'monthly'].includes(newBackupJob.schedule) ? newBackupJob.schedule : 'custom'}
                                                            onChange={e => {
                                                                if(e.target.value === 'custom') {
                                                                    setNewBackupJob({...newBackupJob, schedule: '02:00'});
                                                                } else {
                                                                    setNewBackupJob({...newBackupJob, schedule: e.target.value});
                                                                }
                                                            }}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="hourly">{t('hourly') || 'Hourly'}</option>
                                                            <option value="daily">{t('daily') || 'Daily'} (02:00)</option>
                                                            <option value="weekly">{t('weekly') || 'Weekly'} (Sun 02:00)</option>
                                                            <option value="monthly">{t('monthly') || 'Monthly'} (1st 02:00)</option>
                                                            <option value="custom">{t('custom') || 'Custom'}</option>
                                                        </select>
                                                        {!['hourly', 'daily', 'weekly', 'monthly'].includes(newBackupJob.schedule) && (
                                                            <input
                                                                type="text"
                                                                value={newBackupJob.schedule}
                                                                onChange={e => setNewBackupJob({...newBackupJob, schedule: e.target.value})}
                                                                placeholder="e.g. 02:00, sat 03:00, *-*-01 04:00"
                                                                className="w-full mt-2 px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm"
                                                            />
                                                        )}
                                                    </div>
                                                </div>
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Node</label>
                                                        <select
                                                            value={newBackupJob.node}
                                                            onChange={e => setNewBackupJob({...newBackupJob, node: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="">{t('allNodes') || 'All Nodes'}</option>
                                                            {(clusterNodes || []).map(n => (
                                                                <option key={n.node} value={n.node}>{n.node}</option>
                                                            ))}
                                                        </select>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Mode</label>
                                                        <select
                                                            value={newBackupJob.mode}
                                                            onChange={e => setNewBackupJob({...newBackupJob, mode: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="snapshot">Snapshot</option>
                                                            <option value="suspend">Suspend</option>
                                                            <option value="stop">Stop</option>
                                                        </select>
                                                    </div>
                                                </div>
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('compression') || 'Compression'}</label>
                                                        <select
                                                            value={newBackupJob.compress}
                                                            onChange={e => setNewBackupJob({...newBackupJob, compress: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="0">None</option>
                                                            <option value="gzip">GZIP</option>
                                                            <option value="lzo">LZO</option>
                                                            <option value="zstd">ZSTD (recommended)</option>
                                                        </select>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">VM IDs ({t('optional')})</label>
                                                        <input
                                                            type="text"
                                                            value={newBackupJob.vmid}
                                                            onChange={e => setNewBackupJob({...newBackupJob, vmid: e.target.value})}
                                                            placeholder="100,101,102 or empty for all"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                </div>
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">{t('notification') || 'Notification'}</label>
                                                        <select
                                                            value={newBackupJob.mailnotification}
                                                            onChange={e => setNewBackupJob({...newBackupJob, mailnotification: e.target.value})}
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        >
                                                            <option value="always">{t('always') || 'Always'}</option>
                                                            <option value="failure">{t('onFailure') || 'On Failure'}</option>
                                                            <option value="never">{t('never') || 'Never'}</option>
                                                        </select>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Email ({t('optional')})</label>
                                                        <input
                                                            type="email"
                                                            value={newBackupJob.mailto}
                                                            onChange={e => setNewBackupJob({...newBackupJob, mailto: e.target.value})}
                                                            placeholder="admin@example.com"
                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white"
                                                        />
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <input
                                                        type="checkbox"
                                                        checked={newBackupJob.enabled === 1}
                                                        onChange={e => setNewBackupJob({...newBackupJob, enabled: e.target.checked ? 1 : 0})}
                                                        className="rounded"
                                                    />
                                                    <label className="text-sm text-gray-300">{t('enabled')}</label>
                                                </div>
                                            </div>
                                            <div className="p-4 border-t border-proxmox-border bg-proxmox-dark flex justify-end gap-3">
                                                <button
                                                    onClick={() => setShowAddBackupJob(false)}
                                                    className="px-4 py-2 text-gray-400 hover:text-white"
                                                >
                                                    {t('cancel')}
                                                </button>
                                                <button
                                                    onClick={createBackupJob}
                                                    disabled={!newBackupJob.storage}
                                                    className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
                                                >
                                                    {t('create')}
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Replication */}
                        {activeSection === 'replication' && (
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                <div className="p-4 border-b border-proxmox-border">
                                    <h3 className="font-semibold">Replication Jobs</h3>
                                </div>
                                <table className="w-full">
                                    <thead className="bg-proxmox-dark">
                                        <tr>
                                            <th className="text-left p-3 text-sm text-gray-400">Enabled</th>
                                            <th className="text-left p-3 text-sm text-gray-400">Guest</th>
                                            <th className="text-left p-3 text-sm text-gray-400">Job</th>
                                            <th className="text-left p-3 text-sm text-gray-400">Target</th>
                                            <th className="text-left p-3 text-sm text-gray-400">Schedule</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {replicationJobs.length === 0 ? (
                                            <tr><td colSpan="5" className="p-8 text-center text-gray-500">{t('noReplicationJobs') || 'No Replication Jobs'}</td></tr>
                                        ) : replicationJobs.map((job, idx) => (
                                            <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                <td className="p-3">{job.disable ? <span className="text-gray-500">✗</span> : <span className="text-green-400">✓</span>}</td>
                                                <td className="p-3">{job.guest}</td>
                                                <td className="p-3">{job.jobnum}</td>
                                                <td className="p-3">{job.target}</td>
                                                <td className="p-3 font-mono text-sm">{job.schedule}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {/* CPU Compatibility Mode (similar to VMware EVC) */}
                        {activeSection === 'cpucompat' && (
                            <div className="space-y-6">
                                {/* Auto-detected recommendation */}
                                {recommendedCpu && cpuInfo.length > 0 && (
                                    <div className="bg-gradient-to-r from-purple-500/20 to-blue-500/20 border border-purple-500/30 rounded-xl p-6">
                                        <div className="flex items-center gap-4">
                                            <div className="p-4 bg-purple-500/20 rounded-xl">
                                                <Icons.Cpu className="w-8 h-8 text-purple-400" />
                                            </div>
                                            <div className="flex-1">
                                                <h3 className="text-lg font-semibold text-white mb-1">{t('autoDetectedRecommendation') || 'Auto-Detected Recommendation'}</h3>
                                                <p className="text-sm text-gray-300 mb-3">
                                                    {t('basedOnClusterCpus') || 'Based on the CPUs detected in your cluster, we recommend:'}
                                                </p>
                                                <div className="flex items-center gap-3">
                                                    <code className="text-xl font-bold text-purple-400 bg-proxmox-dark px-4 py-2 rounded-lg">
                                                        cpu: {recommendedCpu}
                                                    </code>
                                                    <button
                                                        onClick={() => {
                                                            navigator.clipboard.writeText(`cpu: ${recommendedCpu}`);
                                                        }}
                                                        className="px-3 py-2 bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 rounded-lg text-sm transition-colors"
                                                    >
                                                        {t('copy') || 'Copy'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                    <div className="flex items-center gap-3 mb-4">
                                        <div className="p-3 bg-purple-500/10 rounded-lg">
                                            <Icons.Cpu className="text-purple-400" />
                                        </div>
                                        <div>
                                            <h3 className="font-semibold text-white">{t('cpuCompatibilityMode') || 'CPU Compatibility Mode'}</h3>
                                            <p className="text-sm text-gray-400">{t('cpuCompatibilityDesc') || 'Ensure live migration compatibility across different CPU generations'}</p>
                                        </div>
                                    </div>
                                    
                                    <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg mb-6">
                                        <h4 className="text-blue-400 font-medium mb-2 flex items-center gap-2">
                                            <Icons.AlertTriangle className="w-4 h-4" />
                                            {t('whatIsCpuCompat') || 'What is CPU Compatibility Mode?'}
                                        </h4>
                                        <p className="text-sm text-gray-300 mb-2">
                                            {t('cpuCompatExplain') || 'When you have nodes with different CPU generations (e.g., Haswell and Skylake), live migration may fail because newer CPUs expose features that older CPUs don\'t support.'}
                                        </p>
                                        <p className="text-sm text-gray-300">
                                            {t('cpuCompatSolution') || 'By setting all VMs to use a common CPU type, you ensure they can migrate between any node in the cluster.'}
                                        </p>
                                    </div>

                                    <div className="space-y-4">
                                        <h4 className="font-medium text-white">{t('availableLevels') || 'Available Compatibility Levels'}</h4>
                                        
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                            {[
                                                { id: 'x86-64-v2-AES', label: 'x86-64-v2-AES', color: 'green', tag: t('safest') || 'Safest', desc: t('broadCompatibility') || 'Broad compatibility - works with most CPUs from 2008+' },
                                                { id: 'x86-64-v3', label: 'x86-64-v3', color: 'blue', tag: t('modern') || 'Modern', desc: t('haswell') || 'Haswell and newer (2013+)' },
                                                { id: 'x86-64-v4', label: 'x86-64-v4', color: 'yellow', tag: t('newest') || 'Newest', desc: t('skylakeAvx') || 'Skylake-X with AVX-512 (2017+)' },
                                                { id: 'host', label: 'host', color: 'red', tag: t('noMigration') || 'No Migration', desc: t('hostDesc') || 'Pass-through host CPU - best performance, no migration' }
                                            ].map(level => (
                                                <div 
                                                    key={level.id}
                                                    onClick={() => navigator.clipboard.writeText(`cpu: ${level.label}`)}
                                                    className={`p-4 bg-proxmox-dark rounded-lg border transition-all cursor-pointer ${
                                                        recommendedCpu === level.id 
                                                            ? 'border-purple-500 ring-2 ring-purple-500/30' 
                                                            : 'border-proxmox-border hover:border-purple-500/50'
                                                    }`}
                                                >
                                                    <div className="flex items-center justify-between mb-2">
                                                        <span className="font-medium text-white">{level.label}</span>
                                                        <div className="flex items-center gap-2">
                                                            {recommendedCpu === level.id && (
                                                                <span className="text-xs px-2 py-1 bg-purple-500/20 text-purple-400 rounded">
                                                                    {t('recommended') || 'Recommended'}
                                                                </span>
                                                            )}
                                                            <span className={`text-xs px-2 py-1 rounded bg-${level.color}-500/20 text-${level.color}-400`}>
                                                                {level.tag}
                                                            </span>
                                                        </div>
                                                    </div>
                                                    <p className="text-xs text-gray-400 mb-2">{level.desc}</p>
                                                    <code className="text-xs bg-proxmox-darker px-2 py-1 rounded font-mono text-purple-400">cpu: {level.label}</code>
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    {/* Detected Node CPUs */}
                                    <div className="mt-6 pt-6 border-t border-proxmox-border">
                                        <h4 className="font-medium text-white mb-4 flex items-center gap-2">
                                            <Icons.Server className="w-4 h-4" />
                                            {t('detectedClusterCpus') || 'Detected Cluster CPUs'}
                                        </h4>
                                        {cpuInfo.length > 0 ? (
                                            <div className="space-y-2">
                                                {cpuInfo.map(info => (
                                                    <div key={info.node} className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                        <div className="flex items-center justify-between">
                                                            <div className="flex items-center gap-3">
                                                                <div className="w-2 h-2 rounded-full bg-green-500" />
                                                                <span className="font-medium text-white">{info.node}</span>
                                                            </div>
                                                            <span className={`text-xs px-2 py-1 rounded ${
                                                                info.detectedLevel === 'v4' ? 'bg-yellow-500/20 text-yellow-400' :
                                                                info.detectedLevel === 'v3' ? 'bg-blue-500/20 text-blue-400' :
                                                                'bg-green-500/20 text-green-400'
                                                            }`}>
                                                                x86-64-{info.detectedLevel}
                                                            </span>
                                                        </div>
                                                        <div className="mt-2 flex items-center justify-between text-sm">
                                                            <span className="text-gray-400 font-mono truncate max-w-md">{info.model}</span>
                                                            <span className="text-gray-500">{info.generation} • {info.sockets}x{info.cores} Cores</span>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        ) : (
                                            <div className="text-center py-6 text-gray-500">
                                                <Icons.Cpu className="w-8 h-8 mx-auto mb-2 opacity-50" />
                                                {t('loadingCpuInfo') || 'Loading CPU information...'}
                                            </div>
                                        )}
                                    </div>

                                    <div className="mt-6 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                        <h4 className="text-yellow-400 font-medium mb-2 flex items-center gap-2">
                                            <Icons.AlertTriangle className="w-4 h-4" />
                                            {t('howToApply') || 'How to Apply'}
                                        </h4>
                                        <ol className="text-sm text-gray-300 space-y-1 list-decimal list-inside">
                                            <li>{t('cpuStep1') || 'Go to each VM\'s Hardware tab'}</li>
                                            <li>{t('cpuStep2') || 'Edit the CPU setting'}</li>
                                            <li>{t('cpuStep3') || 'Change "Type" to your chosen compatibility level'}</li>
                                            <li>{t('cpuStep4') || 'Restart the VM for changes to take effect'}</li>
                                        </ol>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* HA - High Availability (Proxmox Native HA) */}
                        {activeSection === 'ha' && (
                            <div className="space-y-6">
                                {/* HA Status */}
                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                    <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                        <h3 className="font-semibold flex items-center gap-2">
                                            <Icons.Activity />
                                            Status
                                        </h3>
                                        <button onClick={fetchAllData} className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark hover:bg-proxmox-border rounded-lg text-sm">
                                            <Icons.RefreshCw className="w-4 h-4" />
                                        </button>
                                    </div>
                                    <div className="p-4 space-y-4">
                                        {haManagerStatus && typeof haManagerStatus === 'object' ? (
                                            <>
                                                {/* Quorum */}
                                                {haManagerStatus.quorum && (
                                                    <div className="flex items-center gap-3 p-3 bg-proxmox-dark/50 rounded-lg">
                                                        <div className={`w-3 h-3 rounded-full ${haManagerStatus.quorum.quorate === '1' || haManagerStatus.quorum.quorate === 1 ? 'bg-green-500' : 'bg-red-500'}`}></div>
                                                        <div>
                                                            <div className="font-medium">Quorum</div>
                                                            <div className="text-sm text-gray-400">
                                                                {haManagerStatus.quorum.quorate === '1' || haManagerStatus.quorum.quorate === 1 ? 'OK' : 'NOT OK'} 
                                                                {haManagerStatus.quorum.node && ` - Node: ${haManagerStatus.quorum.node}`}
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                                
                                                {/* Manager Status */}
                                                {haManagerStatus.manager_status && (
                                                    <div className="p-3 bg-proxmox-dark/50 rounded-lg">
                                                        <div className="font-medium mb-2">Manager Status</div>
                                                        <div className="grid grid-cols-2 gap-2 text-sm">
                                                            <div className="text-gray-400">Master Node:</div>
                                                            <div className="text-green-400 font-mono">{String(haManagerStatus.manager_status.master_node || '-')}</div>
                                                        </div>
                                                        {haManagerStatus.manager_status.node_status && (
                                                            <div className="mt-2">
                                                                <div className="text-gray-400 text-sm mb-1">Node Status:</div>
                                                                <div className="flex flex-wrap gap-2">
                                                                    {Object.entries(haManagerStatus.manager_status.node_status).filter(([k]) => k !== '').map(([node, status]) => (
                                                                        <span key={node} className={`px-2 py-1 rounded text-xs ${status === 'online' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                                                                            {node}: {String(status)}
                                                                        </span>
                                                                    ))}
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                                
                                                {/* LRM Status */}
                                                {haManagerStatus.lrm_status && (
                                                    <div className="p-3 bg-proxmox-dark/50 rounded-lg">
                                                        <div className="font-medium mb-2">LRM Status (Local Resource Manager)</div>
                                                        <div className="space-y-2">
                                                            {Object.entries(haManagerStatus.lrm_status).filter(([k]) => k !== '').map(([node, data]) => (
                                                                <div key={node} className="flex items-center justify-between text-sm p-2 bg-proxmox-dark rounded">
                                                                    <span className="font-mono">{node}</span>
                                                                    <span className={`px-2 py-0.5 rounded text-xs ${data && data.mode === 'active' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                                                                        {data ? String(data.mode || 'unknown') : 'unknown'}
                                                                    </span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}
                                            </>
                                        ) : (
                                            <p className="text-gray-500 text-center py-4">No HA status available</p>
                                        )}
                                    </div>
                                </div>

                                {/* HA Resources */}
                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                    <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                        <h3 className="font-semibold flex items-center gap-2">
                                            <Icons.Server />
                                            Resources
                                        </h3>
                                        <button onClick={async () => {
                                            // Fetch available VMs/CTs when opening modal
                                            try {
                                                var res = await authFetch(API_URL + '/clusters/' + clusterId + '/resources');
                                                if (res && res.ok) {
                                                    var allResources = await res.json();
                                                    // Filter to VMs and CTs not already in HA
                                                    var haIds = (haResources || []).map(function(r) { return r.sid; });
                                                    var available = (allResources || []).filter(function(r) {
                                                        var sid = (r.type === 'qemu' ? 'vm:' : 'ct:') + r.vmid;
                                                        return (r.type === 'qemu' || r.type === 'lxc') && !haIds.includes(sid);
                                                    });
                                                    setAvailableVmsForHa(available);
                                                }
                                            } catch(e) { console.error('Failed to fetch VMs:', e); }
                                            setNewHaResource({ sid: '', state: 'started', group: '', max_restart: 1, max_relocate: 1, comment: '' });
                                            setShowAddHaResource(true);
                                        }} className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm">
                                            <Icons.Plus className="w-4 h-4" /> Add
                                        </button>
                                    </div>
                                    <div className="overflow-x-auto">
                                        <table className="w-full">
                                            <thead>
                                                <tr className="text-left text-gray-400 text-sm bg-proxmox-dark/50">
                                                    <th className="p-3">ID</th>
                                                    <th className="p-3">State</th>
                                                    <th className="p-3">Node</th>
                                                    <th className="p-3">Max Restart</th>
                                                    <th className="p-3">Max Relocate</th>
                                                    <th className="p-3">Group</th>
                                                    <th className="p-3">Comment</th>
                                                    <th className="p-3">Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {haResources && Array.isArray(haResources) && haResources.length > 0 ? (
                                                    haResources.map((res, idx) => (
                                                        <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/30">
                                                            <td className="p-3 font-mono text-sm">{String(res.sid || '')}</td>
                                                            <td className="p-3">
                                                                <span className={`px-2 py-1 rounded text-xs ${
                                                                    res.state === 'started' ? 'bg-green-500/20 text-green-400' :
                                                                    res.state === 'stopped' ? 'bg-gray-500/20 text-gray-400' :
                                                                    res.state === 'error' ? 'bg-red-500/20 text-red-400' :
                                                                    'bg-yellow-500/20 text-yellow-400'
                                                                }`}>
                                                                    {String(res.state || 'unknown')}
                                                                </span>
                                                            </td>
                                                            <td className="p-3">{String(res.node || '-')}</td>
                                                            <td className="p-3">{res.max_restart !== undefined ? res.max_restart : 1}</td>
                                                            <td className="p-3">{res.max_relocate !== undefined ? res.max_relocate : 1}</td>
                                                            <td className="p-3">{String(res.group || '-')}</td>
                                                            <td className="p-3 text-gray-400 text-sm max-w-xs truncate">{String(res.comment || '-')}</td>
                                                            <td className="p-3">
                                                                <button 
                                                                    onClick={async () => {
                                                                        if (confirm('Remove ' + res.sid + ' from HA?')) {
                                                                            try {
                                                                                var r = await authFetch(API_URL + '/clusters/' + clusterId + '/proxmox-ha/resources/' + res.sid, { method: 'DELETE' });
                                                                                if (r && r.ok) { addToast('Removed', 'success'); fetchAllData(); }
                                                                                else { addToast('Failed', 'error'); }
                                                                            } catch(e) { addToast('Error', 'error'); }
                                                                        }
                                                                    }}
                                                                    className="p-1.5 hover:bg-red-500/20 rounded text-gray-400 hover:text-red-400"
                                                                    title="Remove from HA"
                                                                >
                                                                    <Icons.Trash2 className="w-4 h-4" />
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    ))
                                                ) : (
                                                    <tr>
                                                        <td colSpan="8" className="p-8 text-center text-gray-500">
                                                            No HA resources configured
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>

                                {/* HA Groups */}
                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                    <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                        <h3 className="font-semibold flex items-center gap-2">
                                            <Icons.Users />
                                            Groups
                                        </h3>
                                        <button onClick={() => setShowAddHaGroup(true)} className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm">
                                            <Icons.Plus className="w-4 h-4" /> Add
                                        </button>
                                    </div>
                                    <div className="overflow-x-auto">
                                        <table className="w-full">
                                            <thead>
                                                <tr className="text-left text-gray-400 text-sm bg-proxmox-dark/50">
                                                    <th className="p-3">Group</th>
                                                    <th className="p-3">Nodes</th>
                                                    <th className="p-3">Restricted</th>
                                                    <th className="p-3">No Failback</th>
                                                    <th className="p-3">Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {haGroups && Array.isArray(haGroups) && haGroups.length > 0 ? (
                                                    haGroups.map((grp, idx) => (
                                                        <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/30">
                                                            <td className="p-3 font-medium">{String(grp.group || '')}</td>
                                                            <td className="p-3 font-mono text-sm">{String(grp.nodes || '-')}</td>
                                                            <td className="p-3">
                                                                <span className={grp.restricted ? 'text-yellow-400' : 'text-gray-500'}>
                                                                    {grp.restricted ? 'Yes' : 'No'}
                                                                </span>
                                                            </td>
                                                            <td className="p-3">
                                                                <span className={grp.nofailback ? 'text-yellow-400' : 'text-gray-500'}>
                                                                    {grp.nofailback ? 'Yes' : 'No'}
                                                                </span>
                                                            </td>
                                                            <td className="p-3">
                                                                <button 
                                                                    onClick={async () => {
                                                                        if (confirm('Delete group ' + grp.group + '?')) {
                                                                            try {
                                                                                var r = await authFetch(API_URL + '/clusters/' + clusterId + '/proxmox-ha/groups/' + grp.group, { method: 'DELETE' });
                                                                                if (r && r.ok) { addToast('Deleted', 'success'); fetchAllData(); }
                                                                                else { addToast('Failed', 'error'); }
                                                                            } catch(e) { addToast('Error', 'error'); }
                                                                        }
                                                                    }}
                                                                    className="p-1.5 hover:bg-red-500/20 rounded text-gray-400 hover:text-red-400"
                                                                    title="Delete group"
                                                                >
                                                                    <Icons.Trash2 className="w-4 h-4" />
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    ))
                                                ) : (
                                                    <tr>
                                                        <td colSpan="5" className="p-8 text-center text-gray-500">
                                                            No HA groups configured
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>

                                {/* Add Resource Modal - Full Options like Proxmox */}
                                {showAddHaResource && (
                                    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50" onClick={() => setShowAddHaResource(false)}>
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 w-full max-w-lg" onClick={e => e.stopPropagation()}>
                                            <h3 className="text-lg font-semibold mb-4">Add: Resource: Container/Virtual Machine</h3>
                                            <div className="grid grid-cols-2 gap-4">
                                                {/* Left Column */}
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">VM:</label>
                                                        <select 
                                                            value={newHaResource.sid || ''} 
                                                            onChange={e => setNewHaResource({...newHaResource, sid: e.target.value})}
                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                                        >
                                                            <option value="">-- Select VM/CT --</option>
                                                            {availableVmsForHa && availableVmsForHa.map(vm => (
                                                                <option key={vm.vmid} value={(vm.type === 'qemu' ? 'vm:' : 'ct:') + vm.vmid}>
                                                                    {vm.vmid} - {vm.name || 'unnamed'} ({vm.type === 'qemu' ? 'VM' : 'CT'})
                                                                </option>
                                                            ))}
                                                        </select>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Max. Restart:</label>
                                                        <input 
                                                            type="number" 
                                                            min="0" 
                                                            max="10" 
                                                            value={newHaResource.max_restart || 1} 
                                                            onChange={e => setNewHaResource({...newHaResource, max_restart: parseInt(e.target.value) || 0})} 
                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" 
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Max. Relocate:</label>
                                                        <input 
                                                            type="number" 
                                                            min="0" 
                                                            max="10" 
                                                            value={newHaResource.max_relocate || 1} 
                                                            onChange={e => setNewHaResource({...newHaResource, max_relocate: parseInt(e.target.value) || 0})} 
                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" 
                                                        />
                                                    </div>
                                                </div>
                                                
                                                {/* Right Column */}
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Group:</label>
                                                        <select 
                                                            value={newHaResource.group || ''} 
                                                            onChange={e => setNewHaResource({...newHaResource, group: e.target.value})}
                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                                        >
                                                            <option value="">-- None --</option>
                                                            {haGroups && Array.isArray(haGroups) && haGroups.map(g => (
                                                                <option key={g.group} value={g.group}>{g.group}</option>
                                                            ))}
                                                        </select>
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm text-gray-400 mb-1">Request State:</label>
                                                        <select 
                                                            value={newHaResource.state || 'started'} 
                                                            onChange={e => setNewHaResource({...newHaResource, state: e.target.value})}
                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                                        >
                                                            <option value="started">started</option>
                                                            <option value="stopped">stopped</option>
                                                            <option value="ignored">ignored</option>
                                                            <option value="disabled">disabled</option>
                                                        </select>
                                                    </div>
                                                </div>
                                                
                                                {/* Comment - Full Width */}
                                                <div className="col-span-2">
                                                    <label className="block text-sm text-gray-400 mb-1">Comment:</label>
                                                    <input 
                                                        type="text"
                                                        value={newHaResource.comment || ''} 
                                                        onChange={e => setNewHaResource({...newHaResource, comment: e.target.value})}
                                                        className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                                        placeholder="Optional comment"
                                                    />
                                                </div>
                                            </div>
                                            
                                            <div className="flex justify-end gap-2 mt-6">
                                                <button onClick={() => setShowAddHaResource(false)} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-border rounded-lg text-sm">Cancel</button>
                                                <button onClick={async function() {
                                                    var sidVal = (newHaResource.sid || '').trim();
                                                    if (!sidVal) { 
                                                        addToast('Please select a VM/CT', 'error'); 
                                                        return; 
                                                    }
                                                    
                                                    try {
                                                        var payload = { 
                                                            sid: sidVal, 
                                                            state: newHaResource.state || 'started', 
                                                            max_restart: newHaResource.max_restart || 1, 
                                                            max_relocate: newHaResource.max_relocate || 1 
                                                        };
                                                        if (newHaResource.group) payload.group = newHaResource.group;
                                                        if (newHaResource.comment) payload.comment = newHaResource.comment;
                                                        
                                                        var res = await authFetch(API_URL + '/clusters/' + clusterId + '/proxmox-ha/resources', { 
                                                            method: 'POST', 
                                                            headers: { 'Content-Type': 'application/json' }, 
                                                            body: JSON.stringify(payload) 
                                                        });
                                                        
                                                        if (res && res.ok) { 
                                                            addToast('Resource added to HA', 'success'); 
                                                            setShowAddHaResource(false); 
                                                            setNewHaResource({ sid: '', state: 'started', group: '', max_restart: 1, max_relocate: 1, comment: '' });
                                                            fetchAllData(); 
                                                        } else { 
                                                            var errData = await res.json().catch(function() { return {}; }); 
                                                            addToast(errData.error || 'Failed to add resource', 'error'); 
                                                        }
                                                    } catch(e) { 
                                                        addToast('Error: ' + e.message, 'error'); 
                                                    }
                                                }} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm">Add</button>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Add Group Modal */}
                                {showAddHaGroup && (
                                    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50" onClick={() => setShowAddHaGroup(false)}>
                                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 w-full max-w-md" onClick={e => e.stopPropagation()}>
                                            <h3 className="text-lg font-semibold mb-4">Add HA Group</h3>
                                            <div className="space-y-4">
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Group Name</label>
                                                    <input value={newHaGroup.group || ''} onChange={e => setNewHaGroup({...newHaGroup, group: e.target.value})} placeholder="e.g. production" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm" />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-400 mb-1">Nodes (with priority)</label>
                                                    <input value={newHaGroup.nodes || ''} onChange={e => setNewHaGroup({...newHaGroup, nodes: e.target.value})} placeholder="node1:1,node2:2,node3:1" className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm font-mono" />
                                                    <span className="text-xs text-gray-500">Lower priority = preferred</span>
                                                </div>
                                                <div className="flex gap-6">
                                                    <label className="flex items-center gap-2 cursor-pointer">
                                                        <input type="checkbox" checked={newHaGroup.restricted === 1} onChange={e => setNewHaGroup({...newHaGroup, restricted: e.target.checked ? 1 : 0})} className="rounded" />
                                                        <span className="text-sm">Restricted</span>
                                                    </label>
                                                    <label className="flex items-center gap-2 cursor-pointer">
                                                        <input type="checkbox" checked={newHaGroup.nofailback === 1} onChange={e => setNewHaGroup({...newHaGroup, nofailback: e.target.checked ? 1 : 0})} className="rounded" />
                                                        <span className="text-sm">No Failback</span>
                                                    </label>
                                                </div>
                                            </div>
                                            <div className="flex justify-end gap-2 mt-6">
                                                <button onClick={() => setShowAddHaGroup(false)} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-border rounded-lg text-sm">Cancel</button>
                                                <button onClick={async () => {
                                                    if (!newHaGroup.group || !newHaGroup.nodes) { addToast('Enter group name and nodes', 'error'); return; }
                                                    try {
                                                        var res = await authFetch(API_URL + '/clusters/' + clusterId + '/proxmox-ha/groups', { 
                                                            method: 'POST', 
                                                            headers: { 'Content-Type': 'application/json' }, 
                                                            body: JSON.stringify(newHaGroup) 
                                                        });
                                                        if (res && res.ok) { 
                                                            addToast('Group created', 'success'); 
                                                            setShowAddHaGroup(false); 
                                                            setNewHaGroup({ group: '', nodes: '', restricted: 0, nofailback: 0 });
                                                            fetchAllData(); 
                                                        } else { 
                                                            var err = await res.json().catch(function() { return {}; }); 
                                                            addToast(err.error || 'Failed to create group', 'error'); 
                                                        }
                                                    } catch(e) { addToast('Error: ' + e.message, 'error'); }
                                                }} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm">Create</button>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Firewall */}
                        {activeSection === 'firewall' && (
                            <div className="space-y-6">
                                {/* Firewall Options Card */}
                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                    <div className="flex items-center justify-between mb-4">
                                        <h3 className="font-semibold flex items-center gap-2">
                                            <Icons.Shield />
                                            {t('firewallOptions')}
                                        </h3>
                                        <button
                                            onClick={async () => {
                                                const newState = !firewallOptions.enable;
                                                try {
                                                    const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/firewall/options`, {
                                                        method: 'PUT',
                                                        headers: { ...authHeaders, 'Content-Type': 'application/json' },
                                                        credentials: 'include',
                                                        body: JSON.stringify({ enable: newState ? 1 : 0 })
                                                    });
                                                    if(res.ok) {
                                                        setFirewallOptions(prev => ({ ...prev, enable: newState }));
                                                    }
                                                } catch(e) {
                                                    console.error('updating firewall:', e);
                                                }
                                            }}
                                            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                                                firewallOptions.enable 
                                                    ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30' 
                                                    : 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
                                            }`}
                                        >
                                            {firewallOptions.enable ? t('enabled') : t('disabled')}
                                        </button>
                                    </div>
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                        <div className="bg-proxmox-dark rounded-lg p-4">
                                            <div className="text-sm text-gray-400 mb-1">Policy In</div>
                                            <select 
                                                value={firewallOptions.policy_in || 'DROP'}
                                                onChange={async (e) => {
                                                    try {
                                                        const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/firewall/options`, {
                                                            method: 'PUT',
                                                            headers: { ...authHeaders, 'Content-Type': 'application/json' },
                                                            credentials: 'include',
                                                            body: JSON.stringify({ policy_in: e.target.value })
                                                        });
                                                        if(res.ok) setFirewallOptions(prev => ({ ...prev, policy_in: e.target.value }));
                                                    } catch(e) {}
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
                                                value={firewallOptions.policy_out || 'ACCEPT'}
                                                onChange={async (e) => {
                                                    try {
                                                        const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/firewall/options`, {
                                                            method: 'PUT',
                                                            headers: { ...authHeaders, 'Content-Type': 'application/json' },
                                                            credentials: 'include',
                                                            body: JSON.stringify({ policy_out: e.target.value })
                                                        });
                                                        if(res.ok) setFirewallOptions(prev => ({ ...prev, policy_out: e.target.value }));
                                                    } catch(e) {}
                                                }}
                                                className="w-full bg-proxmox-darker border border-proxmox-border rounded-lg p-2 text-white"
                                            >
                                                <option value="ACCEPT">ACCEPT</option>
                                                <option value="DROP">DROP</option>
                                                <option value="REJECT">REJECT</option>
                                            </select>
                                        </div>
                                        <div className="bg-proxmox-dark rounded-lg p-4">
                                            <div className="text-sm text-gray-400 mb-1">Log Level</div>
                                            <select 
                                                value={firewallOptions.log_level_in || 'nolog'}
                                                onChange={async (e) => {
                                                    try {
                                                        const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/firewall/options`, {
                                                            method: 'PUT',
                                                            headers: { ...authHeaders, 'Content-Type': 'application/json' },
                                                            credentials: 'include',
                                                            body: JSON.stringify({ log_level_in: e.target.value })
                                                        });
                                                        if(res.ok) setFirewallOptions(prev => ({ ...prev, log_level_in: e.target.value }));
                                                    } catch(e) {}
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

                                {/* Firewall Rules Card */}
                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                    <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                        <h3 className="font-semibold">{t('firewallRules')}</h3>
                                        <button 
                                            onClick={() => setShowAddRuleModal(true)}
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
                                                {(!firewallRules || firewallRules.length === 0) ? (
                                                    <tr><td colSpan="11" className="p-8 text-center text-gray-500">{t('noFirewallRules')}</td></tr>
                                                ) : (Array.isArray(firewallRules) ? firewallRules : []).map((rule, idx) => (
                                                    <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                        <td className="p-3 text-gray-400">{rule.pos}</td>
                                                        <td className="p-3">
                                                            <span className={`px-2 py-0.5 rounded text-xs ${
                                                                rule.type === 'in' ? 'bg-blue-500/20 text-blue-400' : 'bg-purple-500/20 text-purple-400'
                                                            }`}>
                                                                {rule.type || 'in'}
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
                                                                        const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/firewall/rules/${rule.pos}`, {
                                                                            method: 'PUT',
                                                                            credentials: 'include',
                                                                            headers: { ...authHeaders, 'Content-Type': 'application/json' },
                                                                            body: JSON.stringify({ enable: rule.enable ? 0 : 1 })
                                                                        });
                                                                        if(res.ok) {
                                                                            setFirewallRules(prev => prev.map(r => 
                                                                                r.pos === rule.pos ? { ...r, enable: rule.enable ? 0 : 1 } : r
                                                                            ));
                                                                        }
                                                                    } catch(e) {}
                                                                }}
                                                                className={`w-8 h-5 rounded-full transition-colors ${rule.enable ? 'bg-green-500' : 'bg-gray-600'}`}
                                                            >
                                                                <div className={`w-4 h-4 rounded-full bg-white transition-transform ${rule.enable ? 'translate-x-3.5' : 'translate-x-0.5'}`}></div>
                                                            </button>
                                                        </td>
                                                        <td className="p-3 text-gray-500 text-xs max-w-32 truncate">{rule.comment || ''}</td>
                                                        <td className="p-3">
                                                            <button 
                                                                onClick={() => deleteFirewallRule(rule.pos)} 
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

                                {/* Add Rule Modal */}
                                {showAddRuleModal && (
                                    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 modal-backdrop" onClick={() => setShowAddRuleModal(false)}>
                                        <div className="w-full max-w-lg bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
                                            <div className="p-4 border-b border-proxmox-border">
                                                <h3 className="font-semibold">Add Firewall Rule</h3>
                                            </div>
                                            <div className="p-4 space-y-4">
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="text-sm text-gray-400 mb-1 block">Direction</label>
                                                        <select 
                                                            value={newRule.type || 'in'}
                                                            onChange={e => setNewRule(p => ({...p, type: e.target.value}))}
                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                        >
                                                            <option value="in">IN</option>
                                                            <option value="out">OUT</option>
                                                        </select>
                                                    </div>
                                                    <div>
                                                        <label className="text-sm text-gray-400 mb-1 block">Action</label>
                                                        <select 
                                                            value={newRule.action || 'ACCEPT'}
                                                            onChange={e => setNewRule(p => ({...p, action: e.target.value}))}
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
                                                            value={newRule.macro || ''}
                                                            onChange={e => setNewRule(p => ({...p, macro: e.target.value || undefined}))}
                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                        >
                                                            <option value="">None</option>
                                                            {['Amanda','Auth','BGP','BitTorrent','Ceph','CephMon','CephOSD','CephMGR','CephMDS',
                                                              'DHCPfwd','DHCPv6','DNS','Dropbox','FTP','GNUnet','GRE','HKP',
                                                              'HTTP','HTTPS','ICMP','ICMPv6','IMAP','IMAPS','IPsec-ah','IPsec-esp',
                                                              'IRC','Jabber','JetDirect','L2TP','LDAP','LDAPS','MDNS','MSSQL',
                                                              'MySQL','NFS','NTP','OSPF','OpenVPN','PCA','PMG','POP3','POP3S',
                                                              'PPtP','Ping','PostgreSQL','Printer','RDP','RIP','RNDC',
                                                              'Razor','Rsh','SANE','SMB','SMBv2','SMTP','SMTPS','SNMP','SPAMD',
                                                              'SSH','SVN','SixXS','Squid','Submission','Syslog','TFTP','Telnet',
                                                              'Tinc','Traceroute','VNC','VXLAN','Webmin'
                                                            ].map(name => (
                                                                <option key={name} value={name}>{name}</option>
                                                            ))}
                                                        </select>
                                                    </div>
                                                    <div>
                                                        <label className="text-sm text-gray-400 mb-1 block">Interface</label>
                                                        <input
                                                            type="text"
                                                            value={newRule.iface || ''}
                                                            onChange={e => setNewRule(p => ({...p, iface: e.target.value}))}
                                                            placeholder="e.g. vmbr0"
                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                        />
                                                    </div>
                                                </div>
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="text-sm text-gray-400 mb-1 block">Protocol</label>
                                                        <select
                                                            value={newRule.proto || ''}
                                                            onChange={e => setNewRule(p => ({...p, proto: e.target.value}))}
                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                        >
                                                            <option value="">Any</option>
                                                            <option value="tcp">TCP</option>
                                                            <option value="udp">UDP</option>
                                                            <option value="icmp">ICMP</option>
                                                        </select>
                                                    </div>
                                                    <div>
                                                        <label className="text-sm text-gray-400 mb-1 block">Dest. Port</label>
                                                        <input 
                                                            type="text"
                                                            value={newRule.dport || ''}
                                                            onChange={e => setNewRule(p => ({...p, dport: e.target.value}))}
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
                                                            value={newRule.source || ''}
                                                            onChange={e => setNewRule(p => ({...p, source: e.target.value}))}
                                                            placeholder="e.g. 10.0.0.0/24"
                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                        />
                                                    </div>
                                                    <div>
                                                        <label className="text-sm text-gray-400 mb-1 block">Destination</label>
                                                        <input 
                                                            type="text"
                                                            value={newRule.dest || ''}
                                                            onChange={e => setNewRule(p => ({...p, dest: e.target.value}))}
                                                            placeholder="e.g. 192.168.1.0/24"
                                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                        />
                                                    </div>
                                                </div>
                                                <div>
                                                    <label className="text-sm text-gray-400 mb-1 block">Comment</label>
                                                    <input 
                                                        type="text"
                                                        value={newRule.comment || ''}
                                                        onChange={e => setNewRule(p => ({...p, comment: e.target.value}))}
                                                        placeholder="Optional description"
                                                        className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2"
                                                    />
                                                </div>
                                                <label className="flex items-center gap-2">
                                                    <input 
                                                        type="checkbox"
                                                        checked={newRule.enable !== 0}
                                                        onChange={e => setNewRule(p => ({...p, enable: e.target.checked ? 1 : 0}))}
                                                        className="w-4 h-4 rounded"
                                                    />
                                                    <span>Enable rule</span>
                                                </label>
                                            </div>
                                            <div className="p-4 border-t border-proxmox-border flex gap-3 justify-end">
                                                <button
                                                    onClick={() => setShowAddRuleModal(false)}
                                                    className="px-4 py-2 bg-proxmox-dark rounded-lg hover:bg-proxmox-hover transition-colors"
                                                >
                                                    {t('cancel')}
                                                </button>
                                                <button
                                                    onClick={async () => {
                                                        try {
                                                            const res = await fetch(`${API_URL}/clusters/${clusterId}/datacenter/firewall/rules`, {
                                                                method: 'POST',
                                                                credentials: 'include',
                                                                headers: { ...authHeaders, 'Content-Type': 'application/json' },
                                                                body: JSON.stringify(newRule)
                                                            });
                                                            if(res.ok) {
                                                                // Refresh rules
                                                                const rulesRes = await authFetch(`${API_URL}/clusters/${clusterId}/datacenter/firewall/rules`);
                                                                if(rulesRes.ok) setFirewallRules(await rulesRes.json());
                                                                setShowAddRuleModal(false);
                                                                setNewRule({ type: 'in', action: 'ACCEPT', enable: 1 });
                                                            }
                                                        } catch(e) {}
                                                    }}
                                                    className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600 transition-colors"
                                                >
                                                    {t('add')}
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {activeSection === 'ceph' && (
                            <div className="space-y-6">
                                {cephLoading ? (
                                    <div className="flex items-center justify-center py-12">
                                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-proxmox-orange"></div>
                                    </div>
                                ) : !cephData || !cephData.available ? (
                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-8 text-center">
                                        <Icons.Database className="w-12 h-12 mx-auto text-gray-600 mb-4" />
                                        <h3 className="text-lg font-semibold mb-2">{t('cephNotInstalled') || 'Ceph Not Installed'}</h3>
                                        <p className="text-gray-400 mb-4">{t('cephNotInstalledDesc') || 'No Ceph cluster has been configured on this Proxmox cluster.'}</p>
                                        <p className="text-gray-500 text-sm">{t('cephInstallHint') || 'To set up Ceph, open a node and use the Ceph tab to initialize.'}</p>
                                    </div>
                                ) : (
                                    <>
                                        {/* Ceph Sub-tabs */}
                                        <div className="flex gap-1 border-b border-proxmox-border pb-2">
                                            {['status', 'osds', 'monitors', 'pools', 'fs'].map(st => (
                                                <button
                                                    key={st}
                                                    onClick={() => setCephSubTab(st)}
                                                    className={`px-4 py-2 rounded-lg text-sm transition-colors ${
                                                        cephSubTab === st
                                                            ? 'bg-proxmox-orange text-white'
                                                            : 'text-gray-400 hover:text-white hover:bg-proxmox-dark'
                                                    }`}
                                                >
                                                    {st === 'status' ? t('cephStatus') || 'Status' :
                                                     st === 'osds' ? 'OSDs' :
                                                     st === 'monitors' ? t('cephMons') || 'Monitors' :
                                                     st === 'pools' ? t('cephPools') || 'Pools' :
                                                     'CephFS'}
                                                </button>
                                            ))}
                                        </div>

                                        {/* Status Tab */}
                                        {cephSubTab === 'status' && (
                                            <div className="space-y-6">
                                                {/* Health Card */}
                                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                                    <h3 className="font-semibold mb-4 flex items-center gap-2">
                                                        <Icons.Activity />
                                                        {t('cephHealth') || 'Cluster Health'}
                                                    </h3>
                                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                                        <div className="bg-proxmox-dark rounded-lg p-4">
                                                            <div className="text-sm text-gray-400 mb-1">{t('status')}</div>
                                                            <div className={`text-xl font-bold ${
                                                                cephData.status?.health?.status === 'HEALTH_OK' ? 'text-green-400' :
                                                                cephData.status?.health?.status === 'HEALTH_WARN' ? 'text-yellow-400' :
                                                                'text-red-400'
                                                            }`}>
                                                                {cephData.status?.health?.status || 'Unknown'}
                                                            </div>
                                                            {cephData.status?.health?.checks && Object.entries(cephData.status.health.checks).map(([k, v]) => (
                                                                <div key={k} className="mt-2 text-xs text-gray-400">
                                                                    <span className={v.severity === 'HEALTH_WARN' ? 'text-yellow-400' : 'text-red-400'}>{k}</span>: {v.summary?.message || ''}
                                                                </div>
                                                            ))}
                                                        </div>
                                                        <div className="bg-proxmox-dark rounded-lg p-4">
                                                            <div className="text-sm text-gray-400 mb-1">PG Status</div>
                                                            <div className="space-y-1 text-sm">
                                                                {cephData.status?.pgmap ? (
                                                                    <>
                                                                        <div>{cephData.status.pgmap.num_pgs || 0} PGs</div>
                                                                        {cephData.status.pgmap.pgs_by_state?.map((s, i) => (
                                                                            <div key={i} className="text-xs text-gray-400">{s.count} {s.state_name}</div>
                                                                        ))}
                                                                    </>
                                                                ) : <div className="text-gray-500">-</div>}
                                                            </div>
                                                        </div>
                                                        <div className="bg-proxmox-dark rounded-lg p-4">
                                                            <div className="text-sm text-gray-400 mb-1">{t('cephCapacity') || 'Capacity'}</div>
                                                            {(() => {
                                                                const total = cephData.status?.pgmap?.bytes_total || 0;
                                                                const used = cephData.status?.pgmap?.bytes_used || 0;
                                                                const pct = total > 0 ? ((used / total) * 100).toFixed(1) : 0;
                                                                const fmt = (b) => { if(!b)return'0 B';const k=1024,s=['B','KB','MB','GB','TB','PB'],i=Math.floor(Math.log(b)/Math.log(k));return(b/Math.pow(k,i)).toFixed(1)+' '+s[i]; };
                                                                return (
                                                                    <>
                                                                        <div className="text-lg font-bold">{pct}%</div>
                                                                        <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                                                                            <div className={`h-2 rounded-full ${pct > 80 ? 'bg-red-500' : pct > 60 ? 'bg-yellow-500' : 'bg-green-500'}`} style={{width: `${Math.min(pct, 100)}%`}}></div>
                                                                        </div>
                                                                        <div className="text-xs text-gray-400 mt-1">{fmt(used)} / {fmt(total)}</div>
                                                                    </>
                                                                );
                                                            })()}
                                                        </div>
                                                    </div>
                                                </div>

                                                {/* Quick Overview */}
                                                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                                                    {[
                                                        { label: 'OSDs', value: cephData.osd?.length || 0, color: 'blue' },
                                                        { label: 'Monitors', value: cephData.mon?.length || 0, color: 'purple' },
                                                        { label: 'Pools', value: cephData.pools?.length || 0, color: 'green' },
                                                        { label: 'MDS', value: cephData.mds?.data?.length || 0, color: 'yellow' },
                                                        { label: 'MGR', value: cephData.mgr ? 1 : 0, color: 'cyan' },
                                                    ].map(item => (
                                                        <div key={item.label} className="bg-proxmox-card border border-proxmox-border rounded-xl p-4 text-center">
                                                            <div className={`text-2xl font-bold text-${item.color}-400`}>{item.value}</div>
                                                            <div className="text-sm text-gray-400">{item.label}</div>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        {/* OSDs Tab */}
                                        {cephSubTab === 'osds' && (
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                    <h3 className="font-semibold">OSDs ({(cephData.osd || []).length})</h3>
                                                    <button onClick={fetchCephData} className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg text-sm transition-colors">
                                                        <Icons.RefreshCw className="w-4 h-4" /> {t('refresh') || 'Refresh'}
                                                    </button>
                                                </div>
                                                <div className="overflow-x-auto">
                                                    <table className="w-full">
                                                        <thead className="bg-proxmox-dark">
                                                            <tr>
                                                                <th className="text-left p-3 text-sm text-gray-400">ID</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">{t('name')}</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">{t('host')}</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">{t('status')}</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">In/Out</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">Class</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">{t('actions')}</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {(!cephData.osd || cephData.osd.length === 0) ? (
                                                                <tr><td colSpan="7" className="p-8 text-center text-gray-500">No OSDs found</td></tr>
                                                            ) : cephData.osd.map((osd) => (
                                                                <tr key={osd.id} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                                    <td className="p-3">{osd.id}</td>
                                                                    <td className="p-3 font-medium">{osd.name || `osd.${osd.id}`}</td>
                                                                    <td className="p-3 text-gray-300">{osd.host || '-'}</td>
                                                                    <td className="p-3">
                                                                        <span className={`px-2 py-0.5 rounded text-xs ${
                                                                            osd.status === 'up' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                                                                        }`}>
                                                                            {osd.status || 'unknown'}
                                                                        </span>
                                                                    </td>
                                                                    <td className="p-3">
                                                                        <span className={`px-2 py-0.5 rounded text-xs ${
                                                                            osd.in ? 'bg-blue-500/20 text-blue-400' : 'bg-yellow-500/20 text-yellow-400'
                                                                        }`}>
                                                                            {osd.in ? 'In' : 'Out'}
                                                                        </span>
                                                                    </td>
                                                                    <td className="p-3 text-gray-300">{osd.device_class || osd.class || '-'}</td>
                                                                    <td className="p-3">
                                                                        <div className="flex gap-1">
                                                                            <button
                                                                                onClick={async () => {
                                                                                    const action = osd.in ? 'out' : 'in';
                                                                                    const host = osd.host || cephNode;
                                                                                    if (!confirm(`Mark OSD ${osd.id} as ${action.toUpperCase()}?`)) return;
                                                                                    try {
                                                                                        await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${host}/ceph/osd/${osd.id}/${action}`, { method: 'POST' });
                                                                                        fetchCephData();
                                                                                    } catch (e) {}
                                                                                }}
                                                                                className="px-2 py-1 text-xs bg-proxmox-dark hover:bg-proxmox-hover rounded transition-colors"
                                                                                title={osd.in ? 'Mark Out' : 'Mark In'}
                                                                            >
                                                                                {osd.in ? 'Out' : 'In'}
                                                                            </button>
                                                                            <button
                                                                                onClick={async () => {
                                                                                    const host = osd.host || cephNode;
                                                                                    try {
                                                                                        await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${host}/ceph/osd/${osd.id}/scrub`, { method: 'POST' });
                                                                                        addToast('Scrub started', 'success');
                                                                                    } catch (e) {}
                                                                                }}
                                                                                className="px-2 py-1 text-xs bg-proxmox-dark hover:bg-proxmox-hover rounded transition-colors"
                                                                                title="Scrub"
                                                                            >
                                                                                Scrub
                                                                            </button>
                                                                        </div>
                                                                    </td>
                                                                </tr>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </div>
                                        )}

                                        {/* Monitors Tab */}
                                        {cephSubTab === 'monitors' && (
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                    <h3 className="font-semibold">{t('cephMons') || 'Monitors'} ({(cephData.mon || []).length})</h3>
                                                    <div className="flex gap-2">
                                                        <button
                                                            onClick={() => setShowCreateMon(true)}
                                                            className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white transition-colors"
                                                        >
                                                            <Icons.Plus /> {t('add')}
                                                        </button>
                                                        <button onClick={fetchCephData} className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg text-sm transition-colors">
                                                            <Icons.RefreshCw className="w-4 h-4" />
                                                        </button>
                                                    </div>
                                                </div>
                                                <div className="overflow-x-auto">
                                                    <table className="w-full">
                                                        <thead className="bg-proxmox-dark">
                                                            <tr>
                                                                <th className="text-left p-3 text-sm text-gray-400">{t('name')}</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">{t('host')}</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">{t('status')}</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">Address</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">{t('actions')}</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {(!cephData.mon || cephData.mon.length === 0) ? (
                                                                <tr><td colSpan="5" className="p-8 text-center text-gray-500">No monitors found</td></tr>
                                                            ) : cephData.mon.map((mon, idx) => (
                                                                <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                                    <td className="p-3 font-medium">{mon.name}</td>
                                                                    <td className="p-3 text-gray-300">{mon.host || mon.name}</td>
                                                                    <td className="p-3">
                                                                        <span className={`px-2 py-0.5 rounded text-xs ${
                                                                            mon.quorum !== false ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                                                                        }`}>
                                                                            {mon.quorum !== false ? 'In Quorum' : 'Not in Quorum'}
                                                                        </span>
                                                                    </td>
                                                                    <td className="p-3 font-mono text-xs text-gray-300">{mon.addr || '-'}</td>
                                                                    <td className="p-3">
                                                                        <button
                                                                            onClick={async () => {
                                                                                if (!confirm(`Delete monitor "${mon.name}"?`)) return;
                                                                                const host = mon.host || mon.name;
                                                                                try {
                                                                                    await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${host}/ceph/mon/${mon.name}`, { method: 'DELETE' });
                                                                                    fetchCephData();
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

                                        {/* Pools Tab */}
                                        {cephSubTab === 'pools' && (
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                    <h3 className="font-semibold">{t('cephPools') || 'Pools'} ({(cephData.pools || []).length})</h3>
                                                    <div className="flex gap-2">
                                                        <button
                                                            onClick={() => setShowCreatePool(true)}
                                                            className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white transition-colors"
                                                        >
                                                            <Icons.Plus /> {t('cephCreatePool') || 'Create Pool'}
                                                        </button>
                                                        <button onClick={fetchCephData} className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg text-sm transition-colors">
                                                            <Icons.RefreshCw className="w-4 h-4" />
                                                        </button>
                                                    </div>
                                                </div>
                                                <div className="overflow-x-auto">
                                                    <table className="w-full">
                                                        <thead className="bg-proxmox-dark">
                                                            <tr>
                                                                <th className="text-left p-3 text-sm text-gray-400">{t('name')}</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">Size</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">Min Size</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">PGs</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">CRUSH Rule</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">{t('actions')}</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {(!cephData.pools || cephData.pools.length === 0) ? (
                                                                <tr><td colSpan="6" className="p-8 text-center text-gray-500">No pools</td></tr>
                                                            ) : cephData.pools.map((pool, idx) => (
                                                                <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                                    <td className="p-3 font-medium">{pool.pool_name || pool.name}</td>
                                                                    <td className="p-3 text-gray-300">{pool.size || '-'}</td>
                                                                    <td className="p-3 text-gray-300">{pool.min_size || '-'}</td>
                                                                    <td className="p-3 text-gray-300">{pool.pg_num || '-'}</td>
                                                                    <td className="p-3 text-gray-300">{pool.crush_rule || '-'}</td>
                                                                    <td className="p-3">
                                                                        <button
                                                                            onClick={async () => {
                                                                                const name = pool.pool_name || pool.name;
                                                                                if (!confirm(`Delete pool "${name}"? This cannot be undone!`)) return;
                                                                                try {
                                                                                    await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${cephNode}/ceph/pool/${name}`, { method: 'DELETE' });
                                                                                    fetchCephData();
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

                                        {/* CephFS Tab */}
                                        {cephSubTab === 'fs' && (
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                                                    <h3 className="font-semibold">CephFS ({(cephData.fs || []).length})</h3>
                                                    <button onClick={fetchCephData} className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark hover:bg-proxmox-hover rounded-lg text-sm transition-colors">
                                                        <Icons.RefreshCw className="w-4 h-4" /> {t('refresh') || 'Refresh'}
                                                    </button>
                                                </div>
                                                {(!cephData.fs || cephData.fs.length === 0) ? (
                                                    <div className="p-8 text-center text-gray-500">No CephFS filesystems configured</div>
                                                ) : (
                                                    <div className="divide-y divide-proxmox-border">
                                                        {cephData.fs.map((fs, idx) => (
                                                            <div key={idx} className="p-4">
                                                                <div className="flex justify-between items-center">
                                                                    <div>
                                                                        <div className="font-medium">{fs.name}</div>
                                                                        <div className="text-sm text-gray-400 mt-1">
                                                                            Metadata Pool: {fs.metadata_pool || '-'} | Data Pools: {(fs.data_pools || []).join(', ') || '-'}
                                                                        </div>
                                                                    </div>
                                                                    <button
                                                                        onClick={async () => {
                                                                            if (!confirm(`Delete CephFS "${fs.name}"? This will destroy all data!`)) return;
                                                                            try {
                                                                                await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${cephNode}/ceph/fs/${fs.name}`, { method: 'DELETE' });
                                                                                fetchCephData();
                                                                            } catch (e) {}
                                                                        }}
                                                                        className="p-1.5 hover:bg-red-500/20 rounded text-red-400 transition-colors"
                                                                    >
                                                                        <Icons.Trash />
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}

                                                {/* MDS Daemons */}
                                                {cephData.mds && (
                                                    <div className="border-t border-proxmox-border">
                                                        <div className="p-4 bg-proxmox-dark">
                                                            <h4 className="font-medium text-sm">{t('cephMds') || 'Metadata Servers'}</h4>
                                                        </div>
                                                        <div className="divide-y divide-proxmox-border">
                                                            {(cephData.mds?.data || []).map((mds, idx) => (
                                                                <div key={idx} className="p-4 flex justify-between items-center">
                                                                    <div>
                                                                        <span className="font-medium">{mds.name}</span>
                                                                        <span className="text-gray-400 ml-2">on {mds.host || '-'}</span>
                                                                    </div>
                                                                    <span className={`px-2 py-0.5 rounded text-xs ${
                                                                        mds.state === 'up:active' ? 'bg-green-500/20 text-green-400' :
                                                                        mds.state?.includes('up') ? 'bg-yellow-500/20 text-yellow-400' :
                                                                        'bg-gray-600/20 text-gray-400'
                                                                    }`}>
                                                                        {mds.state || mds.status || 'unknown'}
                                                                    </span>
                                                                </div>
                                                            ))}
                                                            {(!cephData.mds?.data || cephData.mds.data.length === 0) && (
                                                                <div className="p-4 text-center text-gray-500 text-sm">No MDS daemons</div>
                                                            )}
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        )}

                                        {/* Create Pool Modal */}
                                        {showCreatePool && (
                                            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 modal-backdrop" onClick={() => setShowCreatePool(false)}>
                                                <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
                                                    <div className="p-4 border-b border-proxmox-border">
                                                        <h3 className="font-semibold">{t('cephCreatePool') || 'Create Pool'}</h3>
                                                    </div>
                                                    <div className="p-4 space-y-4">
                                                        <div>
                                                            <label className="text-sm text-gray-400 mb-1 block">{t('name')}</label>
                                                            <input type="text" value={newPool.name} onChange={e => setNewPool(p => ({...p, name: e.target.value}))} placeholder="e.g. mypool" className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2" />
                                                        </div>
                                                        <div className="grid grid-cols-3 gap-4">
                                                            <div>
                                                                <label className="text-sm text-gray-400 mb-1 block">Size</label>
                                                                <input type="number" min="1" max="7" value={newPool.size} onChange={e => setNewPool(p => ({...p, size: parseInt(e.target.value)}))} className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2" />
                                                            </div>
                                                            <div>
                                                                <label className="text-sm text-gray-400 mb-1 block">Min Size</label>
                                                                <input type="number" min="1" max="7" value={newPool.min_size} onChange={e => setNewPool(p => ({...p, min_size: parseInt(e.target.value)}))} className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2" />
                                                            </div>
                                                            <div>
                                                                <label className="text-sm text-gray-400 mb-1 block">PGs</label>
                                                                <select value={newPool.pg_num} onChange={e => setNewPool(p => ({...p, pg_num: parseInt(e.target.value)}))} className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2">
                                                                    {[8,16,32,64,128,256,512,1024].map(n => <option key={n} value={n}>{n}</option>)}
                                                                </select>
                                                            </div>
                                                        </div>
                                                        {cephNode && <div className="text-xs text-gray-500">Creating on node: {cephNode}</div>}
                                                    </div>
                                                    <div className="p-4 border-t border-proxmox-border flex gap-3 justify-end">
                                                        <button onClick={() => setShowCreatePool(false)} className="px-4 py-2 bg-proxmox-dark rounded-lg hover:bg-proxmox-hover transition-colors">{t('cancel')}</button>
                                                        <button
                                                            onClick={async () => {
                                                                if (!newPool.name || !cephNode) return;
                                                                try {
                                                                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${cephNode}/ceph/pool`, {
                                                                        method: 'POST',
                                                                        headers: { 'Content-Type': 'application/json' },
                                                                        body: JSON.stringify(newPool)
                                                                    });
                                                                    if (res?.ok) {
                                                                        setShowCreatePool(false);
                                                                        setNewPool({ name: '', size: 3, min_size: 2, pg_num: 128 });
                                                                        fetchCephData();
                                                                    }
                                                                } catch (e) {}
                                                            }}
                                                            className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600 transition-colors"
                                                        >
                                                            {t('create') || 'Create'}
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        )}

                                        {/* Create Monitor Modal */}
                                        {showCreateMon && (
                                            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 modal-backdrop" onClick={() => setShowCreateMon(false)}>
                                                <div className="w-full max-w-md bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
                                                    <div className="p-4 border-b border-proxmox-border">
                                                        <h3 className="font-semibold">{t('cephCreateMon') || 'Create Monitor'}</h3>
                                                    </div>
                                                    <div className="p-4 space-y-4">
                                                        <div>
                                                            <label className="text-sm text-gray-400 mb-1 block">{t('node')}</label>
                                                            <select value={cephNode} onChange={e => setCephNode(e.target.value)} className="w-full bg-proxmox-dark border border-proxmox-border rounded-lg p-2">
                                                                {(clusterNodes || []).filter(n => n.online !== 0).map(n => (
                                                                    <option key={n.name} value={n.name}>{n.name}</option>
                                                                ))}
                                                            </select>
                                                        </div>
                                                    </div>
                                                    <div className="p-4 border-t border-proxmox-border flex gap-3 justify-end">
                                                        <button onClick={() => setShowCreateMon(false)} className="px-4 py-2 bg-proxmox-dark rounded-lg hover:bg-proxmox-hover transition-colors">{t('cancel')}</button>
                                                        <button
                                                            onClick={async () => {
                                                                if (!cephNode) return;
                                                                try {
                                                                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${cephNode}/ceph/mon/${cephNode}`, { method: 'POST' });
                                                                    if (res?.ok) {
                                                                        setShowCreateMon(false);
                                                                        fetchCephData();
                                                                    }
                                                                } catch (e) {}
                                                            }}
                                                            className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600 transition-colors"
                                                        >
                                                            {t('create') || 'Create'}
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        )}
                                    </>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Node Join Wizard Modal */}
                    {showNodeJoinWizard && <NodeJoinWizard isOpen={showNodeJoinWizard} onClose={() => setShowNodeJoinWizard(false)} clusterId={clusterId} onSuccess={() => { fetchAllData(); }} addToast={addToast} />}
                    
                    {/* Remove Node Modal */}
                    {showRemoveNodeModal && nodeToRemove && <RemoveNodeConfirmModal isOpen={showRemoveNodeModal} onClose={() => { setShowRemoveNodeModal(false); setNodeToRemove(null); }} node={nodeToRemove} clusterId={clusterId} onSuccess={() => { fetchAllData(); }} addToast={addToast} />}
                </div>
            );
        }

