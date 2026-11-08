        // ═══════════════════════════════════════════════
        // PegaProx - Networking
        // Cluster-wide network overview with VM mapping
        // ═══════════════════════════════════════════════
        // NS: Mar 2026 - Corporate layout network tab
        function NetworkTab({ clusterId, addToast, initialNetwork }) {
            const { t } = useTranslation();
            const { getAuthHeaders, isAdmin } = useAuth();
            const { isCorporate } = useLayout();
            const [loading, setLoading] = useState(true);
            const [networks, setNetworks] = useState([]);
            const [selectedNetwork, setSelectedNetwork] = useState(null);
            const [searchTerm, setSearchTerm] = useState('');
            const [expandedBridges, setExpandedBridges] = useState({});

            const authFetch = async (url, opts = {}) => {
                try {
                    return await fetch(url, { ...opts, credentials: 'include', headers: { ...opts.headers, ...getAuthHeaders() } });
                } catch { return null; }
            };

            // load networks for this cluster
            const fetchNetworks = async () => {
                setLoading(true);
                try {
                    const resp = await authFetch(`${API_URL}/clusters/${clusterId}/networks`);
                    if (resp && resp.ok) {
                        const data = await resp.json();
                        setNetworks(data.networks || []);
                        // auto-select from sidebar click or pick first
                        if (data.networks?.length > 0) {
                            const pick = initialNetwork && data.networks.find(n => n.name === initialNetwork)
                                ? initialNetwork : (selectedNetwork || data.networks[0].name);
                            setSelectedNetwork(pick);
                        }
                    } else {
                        // endpoint returned error - show empty state
                        setNetworks([]);
                    }
                } catch (err) {
                    console.error('fetch networks:', err);
                    setNetworks([]);
                }
                setLoading(false);
            };

            useEffect(() => {
                if (clusterId) fetchNetworks();
                return () => { setNetworks([]); setSelectedNetwork(null); };
            }, [clusterId]);

            // sidebar click → jump to that network
            useEffect(() => {
                if (initialNetwork && networks.length > 0) {
                    setSelectedNetwork(initialNetwork);
                }
            }, [initialNetwork]);

            const filteredNetworks = searchTerm
                ? networks.filter(n => n.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                    n.comments?.toLowerCase().includes(searchTerm.toLowerCase()))
                : networks;

            const selected = networks.find(n => n.name === selectedNetwork);

            // LW: status dot for VM list
            const statusDot = (status) => {
                const color = status === 'running' ? '#60b515' : status === 'stopped' ? 'var(--corp-text-muted)' : '#efc006';
                return <span className="inline-block w-2 h-2 rounded-full mr-1.5" style={{background: color}} />;
            };

            if (loading) {
                return (
                    <div className="flex items-center justify-center py-20">
                        <Icons.RotateCw className="w-6 h-6 animate-spin" style={{color: isCorporate ? 'var(--corp-accent)' : undefined}} />
                        <span className="ml-3 text-gray-400">{t('loading')}...</span>
                    </div>
                );
            }

            if (!networks.length) {
                return (
                    <div className="flex flex-col items-center justify-center py-20 text-gray-500">
                        <Icons.Network className="w-10 h-10 mb-3 opacity-40" />
                        <span>{t('noNetworkData')}</span>
                    </div>
                );
            }

            // corporate layout - split pane
            if (isCorporate) {
                return (
                    <div className="flex h-full" style={{minHeight: '500px'}}>
                        {/* Left panel - network list */}
                        <div className="w-64 flex-shrink-0 border-r" style={{borderColor: 'var(--corp-border-medium)', background: 'var(--corp-bar-track)'}}>
                            <div className="p-2 border-b" style={{borderColor: 'var(--corp-border-medium)'}}>
                                <div className="relative">
                                    <Icons.Search className="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2" style={{color: 'var(--corp-text-muted)'}} />
                                    <input
                                        value={searchTerm} onChange={e => setSearchTerm(e.target.value)}
                                        placeholder={t('search') + '...'}
                                        className="w-full pr-2 py-1 text-[13px] bg-transparent border rounded text-white placeholder-gray-500"
                                        style={{paddingLeft: '28px', borderColor: 'var(--corp-border-medium)'}}
                                    />
                                </div>
                            </div>
                            <div className="overflow-y-auto" style={{maxHeight: 'calc(100vh - 280px)'}}>
                                {filteredNetworks.map(net => {
                                    const isActive = net.active;
                                    const vmCount = net.vms?.length || 0;
                                    const isSel = selectedNetwork === net.name;
                                    return (
                                        <div
                                            key={net.name}
                                            onClick={() => setSelectedNetwork(net.name)}
                                            className="flex items-center gap-2 px-3 py-1.5 cursor-pointer text-[13px]"
                                            style={isSel
                                                ? {background: '#324f61', color: '#e9ecef'}
                                                : {color: isActive ? 'var(--corp-text-secondary)' : 'var(--corp-text-muted)'}}
                                            onMouseEnter={e => { if (!isSel) { e.currentTarget.style.background = '#29414e'; }}}
                                            onMouseLeave={e => { if (!isSel) { e.currentTarget.style.background = ''; }}}
                                        >
                                            <Icons.Network className="w-4 h-4 flex-shrink-0" style={{color: isActive ? 'var(--corp-accent)' : 'var(--corp-text-muted)'}} />
                                            <span className="flex-1 truncate">{net.name}</span>
                                            <span className="text-[11px]" style={{color: 'var(--corp-text-muted)'}}>{vmCount}</span>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>

                        {/* Right panel - detail */}
                        <div className="flex-1 overflow-y-auto">
                            {selected ? (
                                <div>
                                    {/* Header */}
                                    <div className="corp-content-header">
                                        <div className="flex items-center gap-2">
                                            <Icons.Network className="w-4 h-4" style={{color: 'var(--corp-accent)'}} />
                                            <span className="font-medium text-white">{selected.name}</span>
                                            {selected.type === 'OVSBridge' && (
                                                <span className="corp-badge-blue text-[10px] px-1.5 py-0.5 rounded">OVS</span>
                                            )}
                                        </div>
                                        <button onClick={fetchNetworks} className="p-1 rounded hover:bg-white/10" title={t('refreshData')}>
                                            <Icons.RotateCw className="w-3.5 h-3.5" style={{color: 'var(--corp-text-muted)'}} />
                                        </button>
                                    </div>

                                    {/* Properties */}
                                    <div className="p-4 space-y-4">
                                        <div className="corp-property-grid">
                                            <span style={{color: 'var(--corp-text-muted)'}}>{t('type')}</span>
                                            <span className="text-white">{selected.type}</span>

                                            {selected.address && <>
                                                <span style={{color: 'var(--corp-text-muted)'}}>IP</span>
                                                <span className="text-white">{selected.cidr || selected.address}</span>
                                            </>}

                                            {selected.gateway && <>
                                                <span style={{color: 'var(--corp-text-muted)'}}>Gateway</span>
                                                <span className="text-white">{selected.gateway}</span>
                                            </>}

                                            {selected.bridge_ports && <>
                                                <span style={{color: 'var(--corp-text-muted)'}}>{t('bridgePorts')}</span>
                                                <span className="text-white">{selected.bridge_ports}</span>
                                            </>}

                                            {selected.comments && <>
                                                <span style={{color: 'var(--corp-text-muted)'}}>{t('description')}</span>
                                                <span className="text-white">{selected.comments}</span>
                                            </>}

                                            <span style={{color: 'var(--corp-text-muted)'}}>{t('presentOnNodes')}</span>
                                            <span className="text-white">{selected.nodes?.join(', ') || '-'}</span>
                                        </div>

                                        {/* Connected VMs section */}
                                        <div>
                                            <div className="corp-section-header" style={{marginBottom: '8px'}}>
                                                {t('connectedVms')} ({selected.vms?.length || 0})
                                            </div>

                                            {selected.vms?.length > 0 ? (
                                                <div className="corp-datagrid">
                                                    <table className="w-full text-[13px]">
                                                        <thead>
                                                            <tr>
                                                                <th className="text-left py-1.5 px-3 font-medium" style={{color: 'var(--corp-text-secondary)'}}>{t('status')}</th>
                                                                <th className="text-left py-1.5 px-3 font-medium" style={{color: 'var(--corp-text-secondary)'}}>{t('name')}</th>
                                                                <th className="text-left py-1.5 px-3 font-medium" style={{color: 'var(--corp-text-secondary)'}}>VMID</th>
                                                                <th className="text-left py-1.5 px-3 font-medium" style={{color: 'var(--corp-text-secondary)'}}>{t('type')}</th>
                                                                <th className="text-left py-1.5 px-3 font-medium" style={{color: 'var(--corp-text-secondary)'}}>{t('node')}</th>
                                                                <th className="text-left py-1.5 px-3 font-medium" style={{color: 'var(--corp-text-secondary)'}}>Interface</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {selected.vms.map((vm, i) => (
                                                                <tr key={`${vm.vmid}-${vm.iface}-${i}`}
                                                                    className="border-t"
                                                                    style={{borderColor: 'var(--corp-divider)'}}
                                                                    onMouseEnter={e => e.currentTarget.style.background = 'var(--color-hover)'}
                                                                    onMouseLeave={e => e.currentTarget.style.background = ''}
                                                                >
                                                                    <td className="py-1.5 px-3 text-white">
                                                                        {statusDot(vm.status)}
                                                                        {vm.status}
                                                                    </td>
                                                                    <td className="py-1.5 px-3 text-white">{vm.name || '-'}</td>
                                                                    <td className="py-1.5 px-3" style={{color: 'var(--corp-text-secondary)'}}>{vm.vmid}</td>
                                                                    <td className="py-1.5 px-3" style={{color: 'var(--corp-text-secondary)'}}>
                                                                        {vm.type === 'qemu' ? 'VM' : 'CT'}
                                                                    </td>
                                                                    <td className="py-1.5 px-3" style={{color: 'var(--corp-text-secondary)'}}>{vm.node}</td>
                                                                    <td className="py-1.5 px-3" style={{color: 'var(--corp-text-muted)'}}>{vm.iface}</td>
                                                                </tr>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            ) : (
                                                <div className="text-center py-6" style={{color: 'var(--corp-text-muted)'}}>
                                                    {t('noVmsOnBridge')}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            ) : (
                                <div className="flex items-center justify-center h-full text-gray-500">
                                    {t('networkOverview')}
                                </div>
                            )}
                        </div>
                    </div>
                );
            }

            // modern layout - simpler card-based view
            return (
                <div className="space-y-4">
                    <div className="flex items-center justify-between">
                        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                            <Icons.Network className="w-5 h-5 text-proxmox-orange" />
                            {t('networkOverview')}
                        </h3>
                        <button onClick={fetchNetworks} className="p-2 rounded-lg bg-proxmox-dark hover:bg-proxmox-hover text-gray-400 hover:text-white transition-colors">
                            <Icons.RotateCw className="w-4 h-4" />
                        </button>
                    </div>

                    <div className="grid gap-3">
                        {filteredNetworks.map(net => {
                            const expanded = expandedBridges[net.name];
                            const vmCount = net.vms?.length || 0;
                            return (
                                <div key={net.name} className="bg-proxmox-dark rounded-lg border border-proxmox-border overflow-hidden">
                                    <div
                                        className="flex items-center justify-between p-3 cursor-pointer hover:bg-proxmox-hover transition-colors"
                                        onClick={() => setExpandedBridges(prev => ({...prev, [net.name]: !prev[net.name]}))}
                                    >
                                        <div className="flex items-center gap-3">
                                            <Icons.Network className={`w-5 h-5 ${net.active ? 'text-blue-400' : 'text-gray-600'}`} />
                                            <div>
                                                <span className="font-medium text-white">{net.name}</span>
                                                {net.cidr && <span className="ml-2 text-sm text-gray-400">{net.cidr}</span>}
                                                {net.comments && <span className="ml-2 text-sm text-gray-500">— {net.comments}</span>}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-3">
                                            <span className="text-sm text-gray-400">
                                                {vmCount} {vmCount === 1 ? 'VM' : 'VMs'}
                                            </span>
                                            <span className="text-xs text-gray-500">{net.nodes?.join(', ')}</span>
                                            <Icons.ChevronDown className={`w-4 h-4 text-gray-500 transition-transform ${expanded ? 'rotate-180' : ''}`} />
                                        </div>
                                    </div>

                                    {expanded && (
                                        <div className="border-t border-proxmox-border">
                                            {net.bridge_ports && (
                                                <div className="px-4 py-2 text-sm">
                                                    <span className="text-gray-500">{t('bridgePorts')}:</span>
                                                    <span className="ml-2 text-gray-300">{net.bridge_ports}</span>
                                                </div>
                                            )}
                                            {vmCount > 0 ? (
                                                <table className="w-full text-sm">
                                                    <thead>
                                                        <tr className="border-b border-proxmox-border">
                                                            <th className="text-left px-4 py-2 text-gray-400 font-medium">{t('name')}</th>
                                                            <th className="text-left px-4 py-2 text-gray-400 font-medium">VMID</th>
                                                            <th className="text-left px-4 py-2 text-gray-400 font-medium">{t('status')}</th>
                                                            <th className="text-left px-4 py-2 text-gray-400 font-medium">{t('node')}</th>
                                                            <th className="text-left px-4 py-2 text-gray-400 font-medium">Interface</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {net.vms.map((vm, i) => (
                                                            <tr key={`${vm.vmid}-${vm.iface}-${i}`} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover/50">
                                                                <td className="px-4 py-1.5 text-white">{vm.name || '-'}</td>
                                                                <td className="px-4 py-1.5 text-gray-300">{vm.vmid}</td>
                                                                <td className="px-4 py-1.5">
                                                                    {statusDot(vm.status)}
                                                                    <span className="text-gray-300">{vm.status}</span>
                                                                </td>
                                                                <td className="px-4 py-1.5 text-gray-400">{vm.node}</td>
                                                                <td className="px-4 py-1.5 text-gray-500">{vm.iface}</td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            ) : (
                                                <div className="px-4 py-3 text-gray-500 text-sm">{t('noVmsOnBridge')}</div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                </div>
            );
        }
