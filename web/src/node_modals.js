        // ═══════════════════════════════════════════════
        // PegaProx - Node Modals
        // NodeShell terminal, NodeModal, ConsoleModal
        // ═══════════════════════════════════════════════
        // Node Shell Terminal Component using xterm.js with SSH
        function NodeShellTerminal({ node, clusterId, addToast }) {
            const { t } = useTranslation();
            const terminalRef = useRef(null);
            const initRef = useRef(false);
            const [status, setStatus] = useState('loading');
            const [showLogin, setShowLogin] = useState(false);
            const [nodeInfo, setNodeInfo] = useState({});
            const [sshPort, setSshPort] = useState(null);
            const [credentials, setCredentials] = useState({ 
                username: 'root', 
                password: '',
                privateKey: '',
                authMethod: 'password',  // 'password' or 'key'
                host: ''  // SSH host/IP (can be edited by user)
            });
            const wsRef = useRef(null);
            const termRef = useRef(null);
            const statusRef = useRef('loading');
            const { sessionId } = useAuth();  // NS: Get session for WebSocket auth

            // Keep statusRef in sync
            useEffect(() => {
                statusRef.current = status;
            }, [status]);

            const sendCredentials = () => {
                if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
                    const authData = {
                        username: credentials.username,
                        password: credentials.authMethod === 'password' ? credentials.password : '',
                        privateKey: credentials.authMethod === 'key' ? credentials.privateKey : '',
                        host: credentials.host || nodeInfo.ip  // Send host/IP
                    };
                    wsRef.current.send(JSON.stringify(authData));
                    setShowLogin(false);
                    setStatus('connecting');
                    if (termRef.current) {
                        const targetHost = credentials.host || nodeInfo.ip;
                        const method = credentials.authMethod === 'key' ? '(SSH Key)' : '';
                        termRef.current.write(`\r\nVerbinde als ${credentials.username}@${targetHost} ${method}...\r\n`);
                    }
                }
            };

            useEffect(() => {
                if (initRef.current) return;
                initRef.current = true;
                
                if (!terminalRef.current) return;

                let term = null;
                let ws = null;
                let fitAddon = null;
                let cleanup = false;

                const loadTerminal = async () => {
                    try {
                        // Load xterm CSS - try local first
                        if (!document.getElementById('xterm-css')) {
                            const link = document.createElement('link');
                            link.id = 'xterm-css';
                            link.rel = 'stylesheet';
                            link.href = '/static/css/xterm.min.css';
                            link.onerror = () => { link.href = 'https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css'; };
                            document.head.appendChild(link);
                        }

                        // Load xterm.js - try local first, with SRI for CDN
                        if (!window.Terminal) {
                            await new Promise((resolve, reject) => {
                                const script = document.createElement('script');
                                script.src = '/static/js/xterm.min.js';
                                script.onload = resolve;
                                script.onerror = () => {
                                    script.src = 'https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js';
                                    if (SRI_HASHES['xterm@5.3.0']) {
                                        script.integrity = SRI_HASHES['xterm@5.3.0'];
                                        script.crossOrigin = 'anonymous';
                                    }
                                    script.onload = resolve;
                                    script.onerror = reject;
                                };
                                document.head.appendChild(script);
                            });
                        }

                        // Load fit addon - try local first
                        if (!window.FitAddon) {
                            await new Promise((resolve, reject) => {
                                const script = document.createElement('script');
                                script.src = '/static/js/xterm-addon-fit.min.js';
                                script.onload = resolve;
                                script.onerror = () => {
                                    script.src = 'https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js';
                                    if (SRI_HASHES['xterm-addon-fit@0.8.0']) {
                                        script.integrity = SRI_HASHES['xterm-addon-fit@0.8.0'];
                                        script.crossOrigin = 'anonymous';
                                    }
                                    script.onload = resolve;
                                    script.onerror = reject;
                                };
                                document.head.appendChild(script);
                            });
                        }

                        if (cleanup) return;

                        // Create terminal
                        term = new window.Terminal({
                            cursorBlink: true,
                            fontSize: 14,
                            fontFamily: 'Menlo, Monaco, "Courier New", monospace',
                            theme: {
                                background: '#1a1a2e',
                                foreground: '#e4e4e7',
                                cursor: '#e4e4e7',
                            }
                        });
                        termRef.current = term;

                        fitAddon = new window.FitAddon.FitAddon();
                        term.loadAddon(fitAddon);
                        term.open(terminalRef.current);
                        setTimeout(() => fitAddon && fitAddon.fit(), 50);  // idk why 50ms but it works

                        setStatus('connecting');
                        term.write('Verbinde zum Server...\r\n');
                        
                        // First, try to get the node IP via API
                        let nodeIp = '';
                        try {
                            term.write('Ermittle Node-IP...\r\n');
                            const ipResponse = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/ip`, { credentials: 'include', headers: { 'X-Session-ID': sessionId }
                            });
                            if (ipResponse.ok) {
                                const ipData = await ipResponse.json();
                                nodeIp = ipData.ip || '';
                                if (nodeIp) {
                                    term.write(`Node-IP: ${nodeIp} (${ipData.source})\r\n`);
                                }
                            }
                        } catch (e) {
                            console.log('Could not fetch node IP:', e);
                            term.write(`\x1b[33m${t('ipFetchFailed')}: ${e.message}\x1b[0m\r\n`);
                        }

                        // Connect WebSocket - Shell runs on main port + 2
                        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                        const mainPort = parseInt(window.location.port) || (window.location.protocol === 'https:' ? 443 : 80);
                        const sshPortNum = mainPort + 2;
                        setSshPort(sshPortNum);
                        const wsUrl = `${wsProtocol}//${window.location.hostname}:${sshPortNum}/api/clusters/${clusterId}/nodes/${node}/shellws?session=${sessionId || ''}&ip=${encodeURIComponent(nodeIp)}`;
                        
                        term.write(`${t('connectingWs')} (Port ${sshPortNum})...\r\n`);
                        console.log('SSH WebSocket connecting to:', wsUrl);
                        
                        ws = new WebSocket(wsUrl);
                        wsRef.current = ws;
                        
                        ws.onopen = () => {
                            console.log('SSH WebSocket connected');
                            term.write(`${t('wsConnected')}\r\n`);
                        };

                        ws.onmessage = (event) => {
                            const data = event.data;
                            
                            // Check for JSON status messages
                            if (typeof data === 'string') {
                                // Try to parse as JSON
                                if (data.startsWith('{')) {
                                    try {
                                        const msg = JSON.parse(data);
                                        // console.log('ws msg:', msg);  // very spammy
                                        
                                        if (msg.status === 'need_credentials') {
                                            setNodeInfo({ 
                                                node: msg.node, 
                                                ip: msg.ip || '',
                                                allowManualIp: msg.allowManualIp || !msg.ip
                                            });
                                            // Pre-fill host if we have an IP
                                            if (msg.ip) {
                                                setCredentials(prev => ({...prev, host: msg.ip}));
                                            }
                                            setShowLogin(true);
                                            setStatus('login');
                                            return;
                                        } else if (msg.status === 'connecting') {
                                            term.write('SSH Verbindung wird aufgebaut...\r\n');
                                            return;
                                        } else if (msg.status === 'connected') {
                                            setStatus('connected');
                                            statusRef.current = 'connected';
                                            term.clear();
                                            return;
                                        } else if (msg.status === 'error') {
                                            term.write(`\r\n\x1b[31m${msg.message}\x1b[0m\r\n`);
                                            setStatus('error');
                                            // Show login again on auth failure
                                            if (msg.message.includes('Login') || msg.message.includes('auth') || msg.message.includes('Host')) {
                                                setTimeout(() => {
                                                    setShowLogin(true);
                                                    setStatus('login');
                                                }, 1500);
                                            }
                                            return;
                                        }
                                    } catch (e) {
                                        // Not valid JSON, write to terminal
                                        term.write(data);
                                    }
                                } else {
                                    // Regular string data
                                    term.write(data);
                                }
                            } else if (data instanceof ArrayBuffer) {
                                term.write(new TextDecoder().decode(data));
                            } else if (data instanceof Blob) {
                                data.arrayBuffer().then(buf => {
                                    term.write(new TextDecoder().decode(buf));
                                });
                            }
                        };

                        ws.onerror = (err) => {
                            console.error('WebSocket error:', err);
                            if (!cleanup) {
                                const isHttps = window.location.protocol === 'https:';
                                const displayPort = sshPort || sshPortNum;
                                
                                // Get translated messages
                                const errorTitle = t('wsConnectionFailed');
                                const certTitle = t('certInstructions');
                                const step1 = t('certStep1');
                                const step2 = t('certStep2');
                                const step3 = t('certStep3');
                                const checkLogs = t('checkServerLogs');
                                
                                term.write('\r\n\x1b[31m═══════════════════════════════════════════\x1b[0m\r\n');
                                term.write(`\x1b[31m  ${errorTitle}\x1b[0m\r\n`);
                                term.write('\x1b[31m═══════════════════════════════════════════\x1b[0m\r\n\r\n');
                                
                                if (isHttps) {
                                    term.write(`\x1b[33m⚠️  ${certTitle}\x1b[0m\r\n\r\n`);
                                    term.write(`\x1b[36m${step1}\x1b[0m\r\n`);
                                    term.write(`   \x1b[4mhttps://${window.location.hostname}:${displayPort}/\x1b[0m\r\n\r\n`);
                                    term.write(`\x1b[36m${step2}\x1b[0m\r\n\r\n`);
                                    term.write(`\x1b[36m${step3}\x1b[0m\r\n\r\n`);
                                } else {
                                    term.write(`\x1b[90m${checkLogs}\x1b[0m\r\n`);
                                }
                                setStatus('error');
                            }
                        };

                        ws.onclose = (event) => {
                            console.log('WebSocket closed:', event.code, event.reason);
                            if (!cleanup) {
                                // Different messages based on close code
                                let msg = 'Verbindung beendet';
                                if (event.code === 1006) {
                                    msg = 'Verbindung unerwartet getrennt';
                                } else if (event.code === 1011) {
                                    msg = 'Server-Fehler';
                                } else if (event.reason) {
                                    msg = event.reason;
                                }
                                term.write(`\r\n\x1b[33m${msg}\x1b[0m\r\n`);
                                term.write(`\x1b[90m(${t('switchTabToReconnect') || 'Switch tab and back to reconnect'})\x1b[0m\r\n`);
                                setStatus('disconnected');
                            }
                        };

                        // Terminal input -> WebSocket (only when connected)
                        term.onData((data) => {
                            if (ws && ws.readyState === WebSocket.OPEN && statusRef.current === 'connected') {
                                ws.send(data);
                            }
                        });

                        // handle resize
                        const handleResize = () => {
                            if (fitAddon) {
                                fitAddon.fit();
                                if (ws && ws.readyState === WebSocket.OPEN && term && statusRef.current === 'connected') {
                                    ws.send(JSON.stringify({
                                        type: 'resize',
                                        cols: term.cols,
                                        rows: term.rows
                                    }));
                                }
                            }
                        };
                        window.addEventListener('resize', handleResize);

                    } catch (err) {
                        console.error('Terminal error:', err);
                        setStatus('error');
                    }
                };

                loadTerminal();

                return () => {
                    cleanup = true;
                    if (ws) ws.close();
                    if (term) term.dispose();
                };
            }, [node, clusterId]);

            return(
                <div className="w-full h-full relative">
                    <div ref={terminalRef} className="w-full h-full" />
                    
                    {/* Loading overlay */}
                    {status === 'loading' && (
                        <div className="absolute inset-0 flex items-center justify-center bg-black/80">
                            <div className="text-center">
                                <div className="animate-spin w-8 h-8 border-2 border-proxmox-orange border-t-transparent rounded-full mx-auto mb-2"></div>
                                <span className="text-gray-400">Lade Terminal...</span>
                            </div>
                        </div>
                    )}
                    
                    {/* Login form overlay - use fixed for reliable centering */}
                    {showLogin && (
                        <div className="fixed inset-0 flex items-center justify-center bg-black/90 z-[100] p-4">
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6 w-full max-w-md shadow-2xl max-h-[85vh] overflow-y-auto">
                                <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                                    <Icons.Terminal />
                                    SSH Login - {nodeInfo.node}
                                </h3>
                                
                                {/* Host/IP - editable */}
                                <div className="mb-4">
                                    <label className="block text-gray-400 text-sm mb-1">
                                        Host / IP
                                        {nodeInfo.allowManualIp && (
                                            <span className="text-yellow-500 ml-2 text-xs">({t('autoDetectionFailed')})</span>
                                        )}
                                    </label>
                                    <input
                                        type="text"
                                        value={credentials.host || nodeInfo.ip || ''}
                                        onChange={(e) => setCredentials({...credentials, host: e.target.value})}
                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white focus:border-proxmox-orange focus:outline-none font-mono"
                                        placeholder="192.168.1.100 oder hostname"
                                    />
                                </div>
                                
                                {/* Auth method tabs */}
                                <div className="flex mb-4 bg-proxmox-dark rounded-lg p-1">
                                    <button
                                        onClick={() => setCredentials({...credentials, authMethod: 'password'})}
                                        className={`flex-1 py-2 px-3 rounded-md text-sm font-medium transition-colors ${
                                            credentials.authMethod === 'password'
                                                ? 'bg-proxmox-orange text-white'
                                                : 'text-gray-400 hover:text-white'
                                        }`}
                                    >
                                        <Icons.Key className="inline w-4 h-4 mr-1" />
                                        Password
                                    </button>
                                    <button
                                        onClick={() => setCredentials({...credentials, authMethod: 'key'})}
                                        className={`flex-1 py-2 px-3 rounded-md text-sm font-medium transition-colors ${
                                            credentials.authMethod === 'key'
                                                ? 'bg-proxmox-orange text-white'
                                                : 'text-gray-400 hover:text-white'
                                        }`}
                                    >
                                        <Icons.FileKey className="inline w-4 h-4 mr-1" />
                                        SSH Key
                                    </button>
                                </div>
                                
                                <div className="space-y-3">
                                    <div>
                                        <label className="block text-gray-400 text-sm mb-1">Username</label>
                                        <input
                                            type="text"
                                            value={credentials.username}
                                            onChange={(e) => setCredentials({...credentials, username: e.target.value})}
                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white focus:border-proxmox-orange focus:outline-none"
                                            placeholder="root"
                                        />
                                    </div>
                                    
                                    {credentials.authMethod === 'password' ? (
                                        <div>
                                            <label className="block text-gray-400 text-sm mb-1">Password</label>
                                            <input
                                                type="password"
                                                value={credentials.password}
                                                onChange={(e) => setCredentials({...credentials, password: e.target.value})}
                                                onKeyDown={(e) => e.key === 'Enter' && credentials.password && sendCredentials()}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white focus:border-proxmox-orange focus:outline-none"
                                                placeholder="••••••••"
                                            />
                                        </div>
                                    ) : (
                                        <>
                                            <div>
                                                <label className="block text-gray-400 text-sm mb-1">
                                                    Private Key
                                                    <span className="text-gray-500 ml-1 text-xs">(id_rsa, id_ed25519, etc.)</span>
                                                </label>
                                                
                                                {/* File upload area */}
                                                <div 
                                                    className="mb-2 border-2 border-dashed border-proxmox-border rounded-lg p-4 text-center cursor-pointer hover:border-proxmox-orange transition-colors"
                                                    onClick={() => document.getElementById('ssh-key-file-input').click()}
                                                    onDragOver={(e) => { e.preventDefault(); e.currentTarget.classList.add('border-proxmox-orange'); }}
                                                    onDragLeave={(e) => { e.preventDefault(); e.currentTarget.classList.remove('border-proxmox-orange'); }}
                                                    onDrop={(e) => {
                                                        e.preventDefault();
                                                        e.currentTarget.classList.remove('border-proxmox-orange');
                                                        const file = e.dataTransfer.files[0];
                                                        if (file) {
                                                            const reader = new FileReader();
                                                            reader.onload = (ev) => setCredentials({...credentials, privateKey: ev.target.result});
                                                            reader.readAsText(file);
                                                        }
                                                    }}
                                                >
                                                    <div className="w-8 h-8 mx-auto mb-2 text-gray-500">
                                                        <svg className="w-full h-full" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                                                        </svg>
                                                    </div>
                                                    <span className="text-gray-400 text-sm">{t('dropKeyFileHere') || 'Drop key file here or click'}</span>
                                                    <input
                                                        id="ssh-key-file-input"
                                                        type="file"
                                                        className="hidden"
                                                        onChange={(e) => {
                                                            const file = e.target.files[0];
                                                            if (file) {
                                                                const reader = new FileReader();
                                                                reader.onload = (ev) => setCredentials({...credentials, privateKey: ev.target.result});
                                                                reader.readAsText(file);
                                                            }
                                                        }}
                                                    />
                                                </div>
                                                
                                                {/* Textarea for paste/edit */}
                                                <textarea
                                                    value={credentials.privateKey}
                                                    onChange={(e) => setCredentials({...credentials, privateKey: e.target.value})}
                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white focus:border-proxmox-orange focus:outline-none font-mono text-xs resize-y"
                                                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA...&#10;-----END OPENSSH PRIVATE KEY-----"
                                                    rows={8}
                                                    style={{minHeight: '120px'}}
                                                />
                                                {credentials.privateKey && (
                                                    <p className="text-xs text-green-400 mt-1">
                                                        ✓ {t('keyLoaded') || 'Key loaded'} ({credentials.privateKey.split('\n').length} {t('lines') || 'lines'})
                                                    </p>
                                                )}
                                            </div>
                                            <div>
                                                <label className="block text-gray-400 text-sm mb-1">
                                                    {t('keyPassphrase') || 'Key Passphrase'} <span className="text-gray-500">({t('optional') || 'optional'})</span>
                                                </label>
                                                <input
                                                    type="password"
                                                    value={credentials.password}
                                                    onChange={(e) => setCredentials({...credentials, password: e.target.value})}
                                                    onKeyDown={(e) => e.key === 'Enter' && credentials.privateKey && sendCredentials()}
                                                    className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white focus:border-proxmox-orange focus:outline-none"
                                                    placeholder={t('ifKeyEncrypted') || 'If key is encrypted...'}
                                                />
                                            </div>
                                        </>
                                    )}
                                    
                                    <div className="flex gap-2 pt-2">
                                        <button
                                            onClick={() => {
                                                setShowLogin(false);
                                                setStatus('disconnected');
                                                if (wsRef.current) wsRef.current.close();
                                                if (termRef.current) termRef.current.write('\r\n\x1b[33mCancelled\x1b[0m\r\n');
                                            }}
                                            className="flex-1 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-500 transition-colors"
                                        >
                                            {t('cancel') || 'Cancel'}
                                        </button>
                                        <button
                                            onClick={sendCredentials}
                                            disabled={
                                                !(credentials.host || nodeInfo.ip) ||
                                                (credentials.authMethod === 'password' ? !credentials.password : !credentials.privateKey)
                                            }
                                            className="flex-1 py-2 bg-proxmox-orange text-white rounded-lg hover:bg-orange-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                        >
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

        // Node Management Modal Component
        // NS: Full node management - shell, network, disks, etc.
        // Shell tab uses xterm.js (web terminal), pretty cool
        // LW: I did the UI, Marcus handled the backend websocket stuff
        function NodeModal({ node, clusterId, onClose, addToast }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();  // NS: Fix - need auth!
            const [activeTab, setActiveTab] = useState('summary');
            const [loading, setLoading] = useState(true);
            const [data, setData] = useState({});
            
            // NS: Disk creation modal state - Dec 2025
            const [diskModal, setDiskModal] = useState({ open: false, type: null });
            const [diskForm, setDiskForm] = useState({
                device: '', name: '', vgname: '', thinpool: '',
                devices: [], raidlevel: 'single', compression: 'on', ashift: 12,
                filesystem: 'ext4', add_storage: true
            });
            const [diskCreating, setDiskCreating] = useState(false);
            const [perfTimeframe, setPerfTimeframe] = useState('hour'); // NS: For performance metrics
            
            const authHeaders = getAuthHeaders();  // NS: Get auth headers

            const tabs = [
                { id: 'summary', label: 'Summary', icon: Icons.Activity },
                { id: 'performance', label: 'Performance', icon: Icons.BarChart },
                { id: 'shell', label: 'Shell', icon: Icons.Terminal },
                { id: 'network', label: 'Network', icon: Icons.Network },
                { id: 'system', label: 'System', icon: Icons.Cog },
                { id: 'disks', label: 'Disks', icon: Icons.HardDrive },
                { id: 'repos', label: 'Repositories', icon: Icons.Package },
                { id: 'tasks', label: 'Tasks', icon: Icons.Play },
                { id: 'subscription', label: 'Subscription', icon: Icons.Shield },
                { id: 'ceph', label: 'Ceph', icon: Icons.Database },
            ];

            useEffect(() => { loadTabData(activeTab); }, [activeTab, perfTimeframe]);

            const loadTabData = async (tab) => {
                setLoading(true);
                try {
                    const endpoints = {
                        summary: [`${API_URL}/clusters/${clusterId}/nodes/${node}/summary`],
                        performance: [`${API_URL}/clusters/${clusterId}/nodes/${node}/rrddata?timeframe=${perfTimeframe}`],
                        network: [`${API_URL}/clusters/${clusterId}/nodes/${node}/network`],
                        system: [
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/dns`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/hosts`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/time`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/syslog?limit=100`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/certificates`,
                        ],
                        disks: [
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/disks`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/disks/lvm`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/disks/lvmthin`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/disks/zfs`,
                        ],
                        repos: [`${API_URL}/clusters/${clusterId}/nodes/${node}/repos`],
                        tasks: [`${API_URL}/clusters/${clusterId}/nodes/${node}/tasks?limit=50`],
                        subscription: [`${API_URL}/clusters/${clusterId}/nodes/${node}/subscription`],
                        ceph: [
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/status`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/osd`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/mon`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/pool`,
                        ],
                    };
                    const urls = endpoints[tab] || [];
                    // NS: Fixed - now using auth headers and credentials!
                    const results = await Promise.all(urls.map(u => fetch(u, { credentials: 'include', headers: authHeaders }).then(r => r.ok ? r.json() : null).catch(() => null)));
                    
                    const newData = { ...data };
                    if (tab === 'summary') newData.summary = results[0];
                    else if (tab === 'network') newData.network = results[0];
                    else if (tab === 'system') {
                        newData.dns = results[0] || {};
                        newData.hosts = results[1]?.data || '';
                        newData.time = results[2] || {};
                        newData.syslog = results[3] || [];
                        newData.certificates = results[4] || [];
                    }
                    else if (tab === 'disks') {
                        newData.disks = results[0] || [];
                        newData.lvm = results[1] || [];
                        newData.lvmthin = results[2] || [];
                        newData.zfs = results[3] || [];
                    }
                    else if (tab === 'performance') newData.performance = results[0] || {};
                    else if (tab === 'repos') newData.repos = results[0]?.repositories || [];
                    else if (tab === 'tasks') newData.tasks = results[0] || [];
                    else if (tab === 'subscription') newData.subscription = results[0] || {};
                    else if (tab === 'ceph') {
                        // Ceph might not be installed - handle gracefully
                        newData.ceph = {
                            status: results[0],
                            osd: results[1] || [],
                            mon: results[2] || [],
                            pools: results[3] || [],
                            available: results[0] !== null
                        };
                    }
                    setData(newData);
                } catch (e) { console.error(e); }
                setLoading(false);
            };

            // NS: minified helpers for this component, dont judge me
            const formatBytes = (b) => { if(!b)return'0 B';const k=1024,s=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k));return(b/Math.pow(k,i)).toFixed(1)+' '+s[i]; };
            const formatUptime = (s) => { if(!s)return'0s';const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);return`${d}d ${h}h ${m}m`; };

            const handleSave = async (endpoint, payload, msg) => {
                try {
                    const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/${endpoint}`, {
                        credentials: 'include',
                        method: endpoint.includes('hosts') ? 'POST' : 'PUT',
                        headers: { 'Content-Type': 'application/json', ...authHeaders },
                        body: JSON.stringify(payload)
                    });
                    addToast(res.ok ? msg : t('error') || 'Error', res.ok ? 'success' : 'error');
                    if (res.ok) loadTabData(activeTab);
                } catch (e) { addToast(t('error') || 'Error', 'error'); }
            };
            
            // NS: Disk creation functions - Dec 2025
            const unusedDisks = (data.disks || []).filter(d => d.used === 'unused' || !d.used);
            
            const openDiskModal = async (type) => {
                setDiskForm({
                    device: '', name: '', vgname: '', thinpool: '',
                    devices: [], raidlevel: 'single', compression: 'on', ashift: 12,
                    filesystem: 'ext4', add_storage: true
                });
                // NS: Make sure disk data is loaded before opening modal
                if (!data.disks || data.disks.length === 0) {
                    await loadTabData('disks');
                }
                setDiskModal({ open: true, type });
            };
            
            const createDisk = async () => {
                const { type } = diskModal;
                let endpoint, body;
                
                if (type === 'lvm') {
                    if (!diskForm.device || !diskForm.name) {
                        addToast('Device and name required', 'error');
                        return;
                    }
                    endpoint = 'disks/lvm';
                    body = { device: diskForm.device, name: diskForm.name, add_storage: diskForm.add_storage };
                } else if (type === 'lvmthin') {
                    // NS: For LVM-thin, device = VG name where thin pool is created
                    if (!diskForm.vgname || !diskForm.name) {
                        addToast('Volume group and pool name required', 'error');
                        return;
                    }
                    endpoint = 'disks/lvmthin';
                    body = { device: diskForm.vgname, name: diskForm.name, add_storage: diskForm.add_storage };
                } else if (type === 'zfs') {
                    if (diskForm.devices.length === 0 || !diskForm.name) {
                        addToast('Device(s) and name required', 'error');
                        return;
                    }
                    endpoint = 'disks/zfs';
                    body = { 
                        devices: diskForm.devices, 
                        name: diskForm.name, 
                        raidlevel: diskForm.raidlevel,
                        compression: diskForm.compression,
                        ashift: diskForm.ashift,
                        add_storage: diskForm.add_storage 
                    };
                } else if (type === 'directory') {
                    if (!diskForm.device || !diskForm.name) {
                        addToast('Device and name required', 'error');
                        return;
                    }
                    endpoint = 'disks/directory';
                    body = { device: diskForm.device, name: diskForm.name, filesystem: diskForm.filesystem, add_storage: diskForm.add_storage };
                }
                
                if (!endpoint) {
                    addToast('Unknown storage type', 'error');
                    return;
                }
                
                setDiskCreating(true);
                try {
                    console.log('Creating disk:', endpoint, body);
                    const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/${endpoint}`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body)
                    });
                    const result = await res.json();
                    console.log('Create disk response:', res.status, result);
                    
                    if (res.ok) {
                        addToast(`${type.toUpperCase()} created successfully`, 'success');
                        setDiskModal({ open: false, type: null });
                        await loadTabData('disks');
                    } else {
                        addToast(result.error || 'Failed to create', 'error');
                    }
                } catch (e) {
                    console.error('Error creating storage:', e);
                    addToast('Error creating storage', 'error');
                } finally {
                    setDiskCreating(false);
                }
            };
            
            // Disk Create Modal Component
            const DiskCreateModal = () => {
                if (!diskModal.open) return null;
                const { type } = diskModal;
                
                return (
                    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70" onClick={() => setDiskModal({ open: false, type: null })}>
                        <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-lg" onClick={e => e.stopPropagation()}>
                            <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                <h3 className="font-semibold text-white">
                                    {type === 'lvm' && 'Create LVM Volume Group'}
                                    {type === 'lvmthin' && 'Create LVM-Thin Pool'}
                                    {type === 'zfs' && 'Create ZFS Pool'}
                                    {type === 'directory' && 'Create Directory Storage'}
                                </h3>
                                <button onClick={() => setDiskModal({ open: false, type: null })} className="p-1 hover:bg-proxmox-dark rounded"><Icons.X /></button>
                            </div>
                            
                            <div className="p-4 space-y-4">
                                {/* Device Selection - for LVM, LVM-Thin (vg), Directory */}
                                {(type === 'lvm' || type === 'directory') && (
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">Device *</label>
                                        <select 
                                            value={diskForm.device} 
                                            onChange={e => setDiskForm({...diskForm, device: e.target.value})}
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                        >
                                            <option value="">Select disk...</option>
                                            {unusedDisks.map(d => (
                                                <option key={d.devpath} value={d.devpath}>
                                                    {d.devpath} - {formatBytes(d.size)} ({d.type || 'hdd'})
                                                </option>
                                            ))}
                                        </select>
                                        {unusedDisks.length === 0 && (
                                            <p className="text-xs text-yellow-400 mt-1">No unused disks available</p>
                                        )}
                                    </div>
                                )}
                                
                                {/* VG Selection for LVM-Thin */}
                                {type === 'lvmthin' && (
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">Volume Group *</label>
                                        <select 
                                            value={diskForm.vgname} 
                                            onChange={e => setDiskForm({...diskForm, vgname: e.target.value})}
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                        >
                                            <option value="">Select VG...</option>
                                            {Array.isArray(data.lvm) && data.lvm.map(v => (
                                                <option key={v.vg} value={v.vg}>
                                                    {v.vg} - {formatBytes(v.free)} free of {formatBytes(v.size)}
                                                </option>
                                            ))}
                                        </select>
                                        {(!Array.isArray(data.lvm) || data.lvm.length === 0) && (
                                            <p className="text-xs text-yellow-400 mt-1">
                                                ⚠️ No LVM Volume Groups found. Create an LVM VG first before creating a thin pool.
                                            </p>
                                        )}
                                    </div>
                                )}
                                
                                {/* Multi-device Selection for ZFS */}
                                {type === 'zfs' && (
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">Devices *</label>
                                        <div className="space-y-1 max-h-32 overflow-y-auto bg-proxmox-dark border border-proxmox-border rounded p-2">
                                            {unusedDisks.length > 0 ? unusedDisks.map(d => (
                                                <label key={d.devpath} className="flex items-center gap-2 text-sm cursor-pointer hover:bg-proxmox-hover p-1 rounded">
                                                    <input 
                                                        type="checkbox"
                                                        checked={diskForm.devices.includes(d.devpath)}
                                                        onChange={e => {
                                                            if (e.target.checked) {
                                                                setDiskForm({...diskForm, devices: [...diskForm.devices, d.devpath]});
                                                            } else {
                                                                setDiskForm({...diskForm, devices: diskForm.devices.filter(x => x !== d.devpath)});
                                                            }
                                                        }}
                                                        className="rounded"
                                                    />
                                                    <span className="font-mono">{d.devpath}</span>
                                                    <span className="text-gray-500">({formatBytes(d.size)}, {d.type || 'hdd'})</span>
                                                </label>
                                            )) : <p className="text-xs text-yellow-400">No unused disks available</p>}
                                        </div>
                                        {diskForm.devices.length > 0 && (
                                            <p className="text-xs text-gray-500 mt-1">{diskForm.devices.length} disk(s) selected</p>
                                        )}
                                    </div>
                                )}
                                
                                {/* Name */}
                                <div>
                                    <label className="block text-sm text-gray-400 mb-1">
                                        {type === 'lvmthin' ? 'Pool Name *' : type === 'zfs' ? 'Pool Name *' : 'Name *'}
                                    </label>
                                    <input 
                                        value={diskForm.name}
                                        onChange={e => setDiskForm({...diskForm, name: e.target.value})}
                                        placeholder={type === 'lvm' ? 'myvg' : type === 'lvmthin' ? 'data' : type === 'zfs' ? 'tank' : 'storage'}
                                        className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                    />
                                </div>
                                
                                {/* ZFS Options */}
                                {type === 'zfs' && (
                                    <>
                                        <div className="grid grid-cols-3 gap-3">
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">RAID Level</label>
                                                <select 
                                                    value={diskForm.raidlevel}
                                                    onChange={e => setDiskForm({...diskForm, raidlevel: e.target.value})}
                                                    className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                                >
                                                    <option value="single">Single</option>
                                                    <option value="mirror">Mirror</option>
                                                    <option value="raid10">RAID10</option>
                                                    <option value="raidz">RAIDZ</option>
                                                    <option value="raidz2">RAIDZ2</option>
                                                    <option value="raidz3">RAIDZ3</option>
                                                </select>
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">Compression</label>
                                                <select 
                                                    value={diskForm.compression}
                                                    onChange={e => setDiskForm({...diskForm, compression: e.target.value})}
                                                    className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                                >
                                                    <option value="on">On (LZ4)</option>
                                                    <option value="off">Off</option>
                                                    <option value="lz4">LZ4</option>
                                                    <option value="zstd">ZSTD</option>
                                                    <option value="gzip">GZIP</option>
                                                    <option value="lzjb">LZJB</option>
                                                </select>
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-400 mb-1">ashift</label>
                                                <select 
                                                    value={diskForm.ashift}
                                                    onChange={e => setDiskForm({...diskForm, ashift: parseInt(e.target.value)})}
                                                    className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                                >
                                                    <option value={9}>9 (512B)</option>
                                                    <option value={12}>12 (4K)</option>
                                                    <option value={13}>13 (8K)</option>
                                                </select>
                                            </div>
                                        </div>
                                        <p className="text-xs text-gray-500">
                                            ℹ️ Use ashift=12 for modern drives (4K sectors). Mirror needs 2+ disks, RAIDZ needs 3+, RAIDZ2 needs 4+.
                                        </p>
                                    </>
                                )}
                                
                                {/* Directory Options */}
                                {type === 'directory' && (
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">Filesystem</label>
                                        <select 
                                            value={diskForm.filesystem}
                                            onChange={e => setDiskForm({...diskForm, filesystem: e.target.value})}
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded p-2 text-sm"
                                        >
                                            <option value="ext4">ext4 (recommended)</option>
                                            <option value="xfs">XFS</option>
                                        </select>
                                    </div>
                                )}
                                
                                {/* Add to PVE Storage */}
                                <label className="flex items-center gap-2 text-sm">
                                    <input 
                                        type="checkbox"
                                        checked={diskForm.add_storage}
                                        onChange={e => setDiskForm({...diskForm, add_storage: e.target.checked})}
                                        className="rounded"
                                    />
                                    Add to Proxmox VE storage configuration
                                </label>
                            </div>
                            
                            <div className="p-4 border-t border-proxmox-border flex justify-end gap-2">
                                <button 
                                    onClick={() => setDiskModal({ open: false, type: null })}
                                    disabled={diskCreating}
                                    className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-hover disabled:opacity-50 rounded-lg text-sm"
                                >
                                    Cancel
                                </button>
                                <button 
                                    onClick={createDisk}
                                    disabled={
                                        diskCreating ||
                                        !diskForm.name || 
                                        (type === 'lvm' && !diskForm.device) ||
                                        (type === 'lvmthin' && !diskForm.vgname) ||
                                        (type === 'zfs' && diskForm.devices.length === 0) ||
                                        (type === 'directory' && !diskForm.device)
                                    }
                                    className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm text-white flex items-center gap-2"
                                >
                                    {diskCreating && <span className="animate-spin">⏳</span>}
                                    {diskCreating ? 'Creating...' : 'Create'}
                                </button>
                            </div>
                        </div>
                    </div>
                );
            };

            return (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 modal-backdrop bg-black/80">
                    <DiskCreateModal />
                    <div className="w-full max-w-6xl max-h-[90vh] bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl animate-scale-in overflow-hidden flex flex-col">
                        <div className="flex items-center justify-between px-6 py-4 border-b border-proxmox-border bg-proxmox-dark">
                            <div className="flex items-center gap-3">
                                <div className="p-2 rounded-lg bg-green-500/10"><Icons.Server /></div>
                                <div><h2 className="font-semibold text-white">{node}</h2><p className="text-xs text-gray-400">Proxmox Node</p></div>
                            </div>
                            <button onClick={onClose} className="p-2 rounded-lg hover:bg-red-500/20 text-gray-400 hover:text-red-400"><Icons.X /></button>
                        </div>

                        <div className="flex items-center gap-1 px-6 py-3 border-b border-proxmox-border bg-proxmox-dark/50 overflow-x-auto">
                            {tabs.map(tab => (
                                <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                                    className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${activeTab === tab.id ? 'bg-proxmox-orange text-white' : 'text-gray-400 hover:text-white hover:bg-proxmox-hover'}`}>
                                    <tab.icon />{tab.label}
                                </button>
                            ))}
                        </div>

                        <div className="flex-1 overflow-y-auto p-6">
                            {loading ? (
                                <div className="flex items-center justify-center h-64"><div className="animate-spin w-8 h-8 border-2 border-proxmox-orange border-t-transparent rounded-full"></div></div>
                            ) : (
                                <>
                                    {activeTab === 'summary' && data.summary && (
                                        <div className="space-y-6">
                                            <div className="grid grid-cols-4 gap-4">
                                                {[
                                                    { label: 'Status', value: data.summary.status, color: 'text-green-400' },
                                                    { label: 'Uptime', value: formatUptime(data.summary.uptime), color: 'text-white' },
                                                    { label: 'CPU', value: `${((data.summary.cpu||0)*100).toFixed(1)}%`, color: 'text-proxmox-orange' },
                                                    { label: 'Load', value: (data.summary.loadavg||[]).join(', '), color: 'text-white' },
                                                ].map((item, i) => (
                                                    <div key={i} className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                        <div className="text-xs text-gray-500 mb-1">{item.label}</div>
                                                        <div className={`text-lg font-semibold ${item.color}`}>{item.value}</div>
                                                    </div>
                                                ))}
                                            </div>
                                            <div className="grid grid-cols-3 gap-4">
                                                {[
                                                    { label: 'Memory', used: data.summary.memory?.used, total: data.summary.memory?.total, color: 'bg-proxmox-orange' },
                                                    { label: 'Swap', used: data.summary.swap?.used, total: data.summary.swap?.total, color: 'bg-blue-500' },
                                                    { label: 'Root FS', used: data.summary.rootfs?.used, total: data.summary.rootfs?.total, color: 'bg-green-500' },
                                                ].map((item, i) => (
                                                    <div key={i} className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                        <div className="text-sm font-medium text-white mb-3">{item.label}</div>
                                                        <div className="space-y-2">
                                                            <div className="flex justify-between text-sm"><span className="text-gray-400">Used</span><span className="text-white">{formatBytes(item.used)}</span></div>
                                                            <div className="flex justify-between text-sm"><span className="text-gray-400">Total</span><span className="text-white">{formatBytes(item.total)}</span></div>
                                                            <div className="w-full bg-proxmox-hover rounded-full h-2">
                                                                <div className={`${item.color} h-2 rounded-full`} style={{ width: `${((item.used||0)/(item.total||1))*100}%` }}></div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                            <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                <div className="text-sm font-medium text-white mb-3">System Info</div>
                                                <div className="grid grid-cols-2 gap-4 text-sm">
                                                    <div><span className="text-gray-400">Kernel:</span><span className="ml-2 text-white font-mono">{data.summary.kversion}</span></div>
                                                    <div><span className="text-gray-400">PVE:</span><span className="ml-2 text-white">{data.summary.pveversion}</span></div>
                                                    <div><span className="text-gray-400">CPU:</span><span className="ml-2 text-white">{data.summary.cpuinfo?.model}</span></div>
                                                    <div><span className="text-gray-400">Cores:</span><span className="ml-2 text-white">{data.summary.cpuinfo?.cores} ({data.summary.cpuinfo?.cpus} CPUs)</span></div>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Performance Tab - NS: Added Jan 2026 */}
                                    {activeTab === 'performance' && (
                                        <div className="space-y-6">
                                            {/* Timeframe Selector */}
                                            <div className="flex items-center justify-between">
                                                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                                                    <Icons.BarChart /> Performance Metrics
                                                </h3>
                                                <div className="flex gap-2">
                                                    {['hour', 'day', 'week', 'month', 'year'].map(tf => (
                                                        <button
                                                            key={tf}
                                                            onClick={() => setPerfTimeframe(tf)}
                                                            className={`px-3 py-1.5 rounded-lg text-sm ${perfTimeframe === tf 
                                                                ? 'bg-proxmox-orange text-white' 
                                                                : 'bg-proxmox-dark text-gray-400 hover:text-white'}`}
                                                        >
                                                            {tf.charAt(0).toUpperCase() + tf.slice(1)}
                                                        </button>
                                                    ))}
                                                </div>
                                            </div>
                                            
                                            {data.performance?.metrics ? (
                                                <div className="space-y-4">
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <LineChart
                                                            data={data.performance.metrics.cpu}
                                                            timestamps={data.performance.timestamps}
                                                            label="CPU Usage"
                                                            color="#f97316"
                                                            unit="%"
                                                            yMin={0}
                                                            yMax={100}
                                                        />
                                                        <LineChart
                                                            data={data.performance.metrics.memory}
                                                            timestamps={data.performance.timestamps}
                                                            label="Memory Usage"
                                                            color="#3b82f6"
                                                            unit="%"
                                                            yMin={0}
                                                            yMax={100}
                                                        />
                                                        <LineChart
                                                            data={data.performance.metrics.iowait}
                                                            timestamps={data.performance.timestamps}
                                                            label="IO Wait"
                                                            color="#eab308"
                                                            unit="%"
                                                        />
                                                        <LineChart
                                                            data={data.performance.metrics.loadavg}
                                                            timestamps={data.performance.timestamps}
                                                            label="Load Average"
                                                            color="#22c55e"
                                                            unit=""
                                                        />
                                                    </div>
                                                    <LineChart
                                                        datasets={[
                                                            { label: 'Net In', data: data.performance.metrics.net_in, color: '#06b6d4' },
                                                            { label: 'Net Out', data: data.performance.metrics.net_out, color: '#8b5cf6' }
                                                        ]}
                                                        timestamps={data.performance.timestamps}
                                                        label="Network I/O"
                                                        unit=" KB/s"
                                                    />
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <LineChart
                                                            data={data.performance.metrics.swap}
                                                            timestamps={data.performance.timestamps}
                                                            label="Swap Usage"
                                                            color="#ec4899"
                                                            unit="%"
                                                            yMin={0}
                                                            yMax={100}
                                                        />
                                                        <LineChart
                                                            data={data.performance.metrics.rootfs}
                                                            timestamps={data.performance.timestamps}
                                                            label="Root FS Usage"
                                                            color="#a855f7"
                                                            unit="%"
                                                            yMin={0}
                                                            yMax={100}
                                                        />
                                                    </div>

                                                    {data.performance.metrics.pressurecpusome && (
                                                        <LineChart
                                                            datasets={[
                                                                { label: 'Some', data: data.performance.metrics.pressurecpusome, color: '#3b82f6' },
                                                                { label: 'Full', data: data.performance.metrics.pressurecpufull, color: '#ef4444' }
                                                            ]}
                                                            timestamps={data.performance.timestamps}
                                                            label="CPU Pressure Stall"
                                                            unit="%"
                                                            yMin={0}
                                                            yMax={100}
                                                        />
                                                    )}
                                                    {data.performance.metrics.pressurememorysome && (
                                                        <LineChart
                                                            datasets={[
                                                                { label: 'Some', data: data.performance.metrics.pressurememorysome, color: '#22c55e' },
                                                                { label: 'Full', data: data.performance.metrics.pressurememoryfull, color: '#ef4444' }
                                                            ]}
                                                            timestamps={data.performance.timestamps}
                                                            label="Memory Pressure Stall"
                                                            unit="%"
                                                            yMin={0}
                                                            yMax={100}
                                                        />
                                                    )}
                                                    {data.performance.metrics.pressureiosome && (
                                                        <LineChart
                                                            datasets={[
                                                                { label: 'Some', data: data.performance.metrics.pressureiosome, color: '#eab308' },
                                                                { label: 'Full', data: data.performance.metrics.pressureiofull, color: '#ef4444' }
                                                            ]}
                                                            timestamps={data.performance.timestamps}
                                                            label="IO Pressure Stall"
                                                            unit="%"
                                                            yMin={0}
                                                            yMax={100}
                                                        />
                                                    )}

                                                    {data.performance.timestamps?.length > 0 && (
                                                        <div className="text-xs text-gray-500 text-center mt-2">
                                                            {formatTime(data.performance.timestamps[0])} - {formatTime(data.performance.timestamps[data.performance.timestamps.length - 1])}
                                                        </div>
                                                    )}
                                                </div>
                                            ) : (
                                                <div className="text-center text-gray-500 py-12">
                                                    <Icons.BarChart className="mx-auto mb-3 w-12 h-12 opacity-50" />
                                                    <p>No performance data available</p>
                                                    <p className="text-sm mt-1">Try refreshing or selecting a different timeframe</p>
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {activeTab === 'shell' && (
                                        <div className="h-full flex flex-col">
                                            <div className="flex items-center justify-between mb-4">
                                                <div className="flex items-center gap-3">
                                                    <Icons.Terminal />
                                                    <span className="text-white font-medium">Node Shell</span>
                                                </div>
                                                <button
                                                    onClick={() => setData({...data, shellFullscreen: true})}
                                                    className="flex items-center gap-2 px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-300 hover:text-white text-sm"
                                                >
                                                    <Icons.Maximize />
                                                    Fullscreen
                                                </button>
                                            </div>
                                            <div className="flex-1 bg-black rounded-lg border border-proxmox-border overflow-hidden min-h-[400px]">
                                                <NodeShellTerminal 
                                                    node={node} 
                                                    clusterId={clusterId} 
                                                    addToast={addToast}
                                                />
                                            </div>
                                        </div>
                                    )}

                                    {activeTab === 'network' && (
                                        <div className="space-y-4">
                                            {/* Action Buttons */}
                                            <div className="flex items-center gap-3 flex-wrap">
                                                <div className="relative">
                                                    <button 
                                                        onClick={() => setData({...data, showCreateMenu: !data.showCreateMenu})}
                                                        className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange rounded-lg text-white text-sm hover:bg-orange-600"
                                                    >
                                                        <Icons.Plus />
                                                        Create
                                                    </button>
                                                    {data.showCreateMenu && (
                                                        <div className="absolute top-full left-0 mt-1 bg-proxmox-card border border-proxmox-border rounded-lg shadow-xl z-10 min-w-[160px]">
                                                            {['bridge', 'bond', 'vlan', 'OVSBridge', 'OVSBond', 'OVSIntPort'].map(ifaceType => (
                                                                <button key={ifaceType} onClick={() => {
                                                                    setData({...data, showCreateMenu: false, editIface: { type: ifaceType, iface: '', isNew: true }});
                                                                }} className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-proxmox-hover hover:text-white">
                                                                    Linux {ifaceType.charAt(0).toUpperCase() + ifaceType.slice(1)}
                                                                </button>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                                <button 
                                                    onClick={async () => {
                                                        try {
                                                            const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/network`, { method: 'PUT', credentials: 'include' });
                                                            if (res.ok) { addToast(t('networkChangesApplied') || 'Network changes applied'); loadTabData('network'); }
                                                            else { const err = await res.json(); addToast(err.error || t('error'), 'error'); }
                                                        } catch (e) { addToast(t('error') || 'Error', 'error'); }
                                                    }}
                                                    className="px-4 py-2 bg-green-600 rounded-lg text-white text-sm hover:bg-green-700"
                                                >
                                                    Apply Configuration
                                                </button>
                                                <button 
                                                    onClick={async () => {
                                                        if (!confirm(t('discardUnappliedChanges'))) return;
                                                        try {
                                                            const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/network`, { method: 'DELETE', credentials: 'include' });
                                                            if (res.ok) { addToast(t('changesReverted') || 'Changes reverted'); loadTabData('network'); }
                                                            else { const err = await res.json(); addToast(err.error || t('error'), 'error'); }
                                                        } catch (e) { addToast(t('error') || 'Error', 'error'); }
                                                    }}
                                                    className="px-4 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-gray-300 text-sm hover:text-white"
                                                >
                                                    Revert
                                                </button>
                                            </div>

                                            {/* Interface List */}
                                            <div className="space-y-2">
                                                {(data.network||[]).map(iface => (
                                                    <div key={iface.iface} className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                        <div className="flex items-center justify-between mb-2">
                                                            <div className="flex items-center gap-3">
                                                                <Icons.Network />
                                                                <span className="font-medium text-white">{iface.iface}</span>
                                                                <span className="text-xs text-gray-500 bg-proxmox-card px-2 py-0.5 rounded">{iface.type}</span>
                                                                {iface.active && <span className="text-xs text-green-400 bg-green-500/10 px-2 py-0.5 rounded">Active</span>}
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                <button 
                                                                    onClick={() => setData({...data, editIface: {...iface, isNew: false}})}
                                                                    className="p-1.5 rounded hover:bg-proxmox-hover text-gray-400 hover:text-white"
                                                                    title="Edit"
                                                                >
                                                                    <Icons.Cog />
                                                                </button>
                                                                <button 
                                                                    onClick={async () => {
                                                                        if (!confirm(`${iface.iface}: ${t('deleteInterfaceConfirm')}`)) return;
                                                                        try {
                                                                            const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/network/${iface.iface}`, { method: 'DELETE', credentials: 'include' });
                                                                            if (res.ok) { addToast(`${iface.iface} ${t('deleted')}`); loadTabData('network'); }
                                                                            else { const err = await res.json(); addToast(err.error || t('error'), 'error'); }
                                                                        } catch (e) { addToast(t('error') || 'Error', 'error'); }
                                                                    }}
                                                                    className="p-1.5 rounded hover:bg-red-500/20 text-gray-400 hover:text-red-400"
                                                                    title="Delete"
                                                                >
                                                                    <Icons.Trash />
                                                                </button>
                                                            </div>
                                                        </div>
                                                        <div className="grid grid-cols-4 gap-4 text-sm">
                                                            {iface.address && <div><span className="text-gray-500">IP:</span><span className="ml-2 text-white font-mono">{iface.address}/{iface.netmask || iface.cidr?.split('/')[1] || ''}</span></div>}
                                                            {iface.gateway && <div><span className="text-gray-500">Gateway:</span><span className="ml-2 text-white font-mono">{iface.gateway}</span></div>}
                                                            {iface.bridge_ports && <div><span className="text-gray-500">Ports:</span><span className="ml-2 text-white">{iface.bridge_ports}</span></div>}
                                                            {iface.slaves && <div><span className="text-gray-500">Slaves:</span><span className="ml-2 text-white">{iface.slaves}</span></div>}
                                                            {iface['vlan-raw-device'] && <div><span className="text-gray-500">VLAN Device:</span><span className="ml-2 text-white">{iface['vlan-raw-device']}</span></div>}
                                                            {iface['vlan-id'] && <div><span className="text-gray-500">VLAN ID:</span><span className="ml-2 text-white">{iface['vlan-id']}</span></div>}
                                                            {iface.bond_mode && <div><span className="text-gray-500">Bond Mode:</span><span className="ml-2 text-white">{iface.bond_mode}</span></div>}
                                                            {iface.comments && <div className="col-span-4"><span className="text-gray-500">Comment:</span><span className="ml-2 text-gray-400">{iface.comments}</span></div>}
                                                        </div>
                                                    </div>
                                                ))}
                                                {(!data.network || data.network.length === 0) && <div className="text-center py-8 text-gray-500">{t('noNetworkInterfaces') || 'No network interfaces'}</div>}
                                            </div>

                                            {/* Edit/Create Interface Modal */}
                                            {data.editIface && (
                                                <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/80">
                                                    <div className="w-full max-w-xl bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                                        <h3 className="text-lg font-semibold text-white mb-4">
                                                            {data.editIface.isNew ? `Create: Linux ${data.editIface.type}` : `Edit: ${data.editIface.iface}`}
                                                        </h3>
                                                        <div className="space-y-4">
                                                            <div className="grid grid-cols-2 gap-4">
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">Name</label>
                                                                    <input type="text" value={data.editIface.iface || ''} 
                                                                        onChange={(e) => setData({...data, editIface: {...data.editIface, iface: e.target.value}})}
                                                                        disabled={!data.editIface.isNew}
                                                                        placeholder={data.editIface.type === 'bridge' ? 'vmbr0' : data.editIface.type === 'bond' ? 'bond0' : 'vlan0'}
                                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm disabled:opacity-50" />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">IPv4/CIDR</label>
                                                                    <input type="text" value={data.editIface.cidr || ''} 
                                                                        onChange={(e) => setData({...data, editIface: {...data.editIface, cidr: e.target.value}})}
                                                                        placeholder="192.168.1.1/24"
                                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">Gateway (IPv4)</label>
                                                                    <input type="text" value={data.editIface.gateway || ''} 
                                                                        onChange={(e) => setData({...data, editIface: {...data.editIface, gateway: e.target.value}})}
                                                                        placeholder="192.168.1.1"
                                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">IPv6/CIDR</label>
                                                                    <input type="text" value={data.editIface.cidr6 || ''} 
                                                                        onChange={(e) => setData({...data, editIface: {...data.editIface, cidr6: e.target.value}})}
                                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">Gateway (IPv6)</label>
                                                                    <input type="text" value={data.editIface.gateway6 || ''} 
                                                                        onChange={(e) => setData({...data, editIface: {...data.editIface, gateway6: e.target.value}})}
                                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">MTU</label>
                                                                    <input type="number" value={data.editIface.mtu || ''} 
                                                                        onChange={(e) => setData({...data, editIface: {...data.editIface, mtu: e.target.value}})}
                                                                        placeholder="1500"
                                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                </div>
                                                            </div>

                                                            {/* Bridge specific */}
                                                            {data.editIface.type === 'bridge' && (
                                                                <div className="grid grid-cols-2 gap-4">
                                                                    <div>
                                                                        <label className="block text-xs text-gray-400 mb-1">Bridge Ports</label>
                                                                        <input type="text" value={data.editIface.bridge_ports || ''} 
                                                                            onChange={(e) => setData({...data, editIface: {...data.editIface, bridge_ports: e.target.value}})}
                                                                            placeholder="ens18"
                                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                    </div>
                                                                    <div className="flex items-center gap-4 pt-5">
                                                                        <label className="flex items-center gap-2 text-sm text-gray-300">
                                                                            <input type="checkbox" checked={data.editIface.bridge_vlan_aware || false} 
                                                                                onChange={(e) => setData({...data, editIface: {...data.editIface, bridge_vlan_aware: e.target.checked}})} />
                                                                            VLAN aware
                                                                        </label>
                                                                    </div>
                                                                </div>
                                                            )}

                                                            {/* Bond specific */}
                                                            {data.editIface.type === 'bond' && (
                                                                <div className="grid grid-cols-2 gap-4">
                                                                    <div>
                                                                        <label className="block text-xs text-gray-400 mb-1">Slaves</label>
                                                                        <input type="text" value={data.editIface.slaves || ''} 
                                                                            onChange={(e) => setData({...data, editIface: {...data.editIface, slaves: e.target.value}})}
                                                                            placeholder="ens18 ens19"
                                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                    </div>
                                                                    <div>
                                                                        <label className="block text-xs text-gray-400 mb-1">Mode</label>
                                                                        <select value={data.editIface.bond_mode || 'balance-rr'} 
                                                                            onChange={(e) => setData({...data, editIface: {...data.editIface, bond_mode: e.target.value}})}
                                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm">
                                                                            <option value="balance-rr">balance-rr</option>
                                                                            <option value="active-backup">active-backup</option>
                                                                            <option value="balance-xor">balance-xor</option>
                                                                            <option value="broadcast">broadcast</option>
                                                                            <option value="802.3ad">LACP (802.3ad)</option>
                                                                            <option value="balance-tlb">balance-tlb</option>
                                                                            <option value="balance-alb">balance-alb</option>
                                                                        </select>
                                                                    </div>
                                                                    <div>
                                                                        <label className="block text-xs text-gray-400 mb-1">Hash Policy</label>
                                                                        <select value={data.editIface.bond_xmit_hash_policy || ''} 
                                                                            onChange={(e) => setData({...data, editIface: {...data.editIface, bond_xmit_hash_policy: e.target.value}})}
                                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm">
                                                                            <option value="">Default</option>
                                                                            <option value="layer2">layer2</option>
                                                                            <option value="layer2+3">layer2+3</option>
                                                                            <option value="layer3+4">layer3+4</option>
                                                                        </select>
                                                                    </div>
                                                                    <div>
                                                                        <label className="block text-xs text-gray-400 mb-1">Bond Primary</label>
                                                                        <input type="text" value={data.editIface['bond-primary'] || ''} 
                                                                            onChange={(e) => setData({...data, editIface: {...data.editIface, 'bond-primary': e.target.value}})}
                                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                    </div>
                                                                </div>
                                                            )}

                                                            {/* VLAN specific */}
                                                            {data.editIface.type === 'vlan' && (
                                                                <div className="grid grid-cols-2 gap-4">
                                                                    <div>
                                                                        <label className="block text-xs text-gray-400 mb-1">VLAN raw device</label>
                                                                        <input type="text" value={data.editIface['vlan-raw-device'] || ''} 
                                                                            onChange={(e) => setData({...data, editIface: {...data.editIface, 'vlan-raw-device': e.target.value}})}
                                                                            placeholder="vmbr0"
                                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                    </div>
                                                                    <div>
                                                                        <label className="block text-xs text-gray-400 mb-1">VLAN Tag</label>
                                                                        <input type="number" value={data.editIface['vlan-id'] || ''} 
                                                                            onChange={(e) => setData({...data, editIface: {...data.editIface, 'vlan-id': e.target.value}})}
                                                                            placeholder="100"
                                                                            className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                    </div>
                                                                </div>
                                                            )}

                                                            <div className="grid grid-cols-2 gap-4">
                                                                <div className="flex items-center gap-2">
                                                                    <input type="checkbox" checked={data.editIface.autostart !== 0} 
                                                                        onChange={(e) => setData({...data, editIface: {...data.editIface, autostart: e.target.checked ? 1 : 0}})} />
                                                                    <span className="text-sm text-gray-300">Autostart</span>
                                                                </div>
                                                                <div>
                                                                    <label className="block text-xs text-gray-400 mb-1">Comment</label>
                                                                    <input type="text" value={data.editIface.comments || ''} 
                                                                        onChange={(e) => setData({...data, editIface: {...data.editIface, comments: e.target.value}})}
                                                                        className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm" />
                                                                </div>
                                                            </div>
                                                        </div>

                                                        <div className="flex justify-end gap-3 mt-6">
                                                            <button onClick={() => setData({...data, editIface: null})}
                                                                className="px-4 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-gray-300 hover:text-white">
                                                                {t('cancel')}
                                                            </button>
                                                            <button onClick={async () => {
                                                                const iface = data.editIface;
                                                                if (!iface.iface) { addToast(t('nameRequired') || 'Name required', 'error'); return; }
                                                                try {
                                                                    const payload = { ...iface };
                                                                    delete payload.isNew;
                                                                    delete payload.active;
                                                                    delete payload.exists;
                                                                    delete payload.families;
                                                                    delete payload.method;
                                                                    delete payload.method6;
                                                                    delete payload.priority;
                                                                    
                                                                    const url = iface.isNew 
                                                                        ? `${API_URL}/clusters/${clusterId}/nodes/${node}/network`
                                                                        : `${API_URL}/clusters/${clusterId}/nodes/${node}/network/${iface.iface}`;
                                                                    const method = iface.isNew ? 'POST' : 'PUT';
                                                                    
                                                                    const res = await fetch(url, {
                                                                        method,
                                                                        headers: { 'Content-Type': 'application/json' },
                                                                        body: JSON.stringify(payload)
                                                                    });
                                                                    if (res.ok) {
                                                                        addToast(iface.isNew ? (t('interfaceCreated') || 'Interface created') : (t('interfaceUpdated') || 'Interface updated'));
                                                                        setData({...data, editIface: null});
                                                                        loadTabData('network');
                                                                    } else {
                                                                        const err = await res.json();
                                                                        addToast(err.error || t('error'), 'error');
                                                                    }
                                                                } catch (e) { addToast(t('error') || 'Error', 'error'); }
                                                            }} className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600">
                                                                {data.editIface.isNew ? 'Create' : 'Save'}
                                                            </button>
                                                        </div>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {activeTab === 'system' && (
                                        <div className="space-y-6">
                                            {/* DNS */}
                                            <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                <div className="flex justify-between items-center mb-4">
                                                    <h4 className="font-medium text-white">DNS</h4>
                                                    <button onClick={() => handleSave('dns', data.dns, t('dnsSaved') || 'DNS saved')} className="px-3 py-1 bg-proxmox-orange rounded text-white text-sm hover:bg-orange-600">{t('save')}</button>
                                                </div>
                                                <div className="grid grid-cols-3 gap-4">
                                                    <div>
                                                        <label className="block text-xs text-gray-400 mb-1">{t('searchDomain') || 'Search Domain'}</label>
                                                        <input type="text" value={data.dns?.search||''} onChange={(e) => setData({...data, dns: {...data.dns, search: e.target.value}})}
                                                            className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-white text-sm" />
                                                    </div>
                                                    <div>
                                                        <label className="block text-xs text-gray-400 mb-1">{t('dnsServer') || 'DNS Server'} 1</label>
                                                        <input type="text" value={data.dns?.dns1||''} onChange={(e) => setData({...data, dns: {...data.dns, dns1: e.target.value}})}
                                                            className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-white text-sm" />
                                                    </div>
                                                    <div>
                                                        <label className="block text-xs text-gray-400 mb-1">{t('dnsServer') || 'DNS Server'} 2</label>
                                                        <input type="text" value={data.dns?.dns2||''} onChange={(e) => setData({...data, dns: {...data.dns, dns2: e.target.value}})}
                                                            className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-white text-sm" />
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Time */}
                                            <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                <h4 className="font-medium text-white mb-3">{t('time') || 'Time'}</h4>
                                                <div className="grid grid-cols-2 gap-4 text-sm">
                                                    <div><span className="text-gray-400">{t('timezone') || 'Timezone'}:</span><span className="ml-2 text-white">{data.time?.timezone || 'UTC'}</span></div>
                                                    <div><span className="text-gray-400">{t('localTime') || 'Local Time'}:</span><span className="ml-2 text-white font-mono">{data.time?.localtime ? new Date(data.time.localtime * 1000).toLocaleString() : 'N/A'}</span></div>
                                                </div>
                                            </div>

                                            {/* Hosts */}
                                            <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                <div className="flex justify-between items-center mb-4">
                                                    <h4 className="font-medium text-white">/etc/hosts</h4>
                                                    <button onClick={() => handleSave('hosts', { data: data.hosts }, t('hostsSaved') || 'Hosts saved')} className="px-3 py-1 bg-proxmox-orange rounded text-white text-sm hover:bg-orange-600">{t('save')}</button>
                                                </div>
                                                <textarea value={data.hosts||''} onChange={(e) => setData({...data, hosts: e.target.value})} rows={5}
                                                    className="w-full px-3 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-white text-sm font-mono resize-none" />
                                            </div>

                                            {/* Certificates */}
                                            <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                <div className="flex justify-between items-center mb-4">
                                                    <h4 className="font-medium text-white">{t('sslCertificates') || 'SSL Certificates'}</h4>
                                                    <button 
                                                        onClick={() => setData({...data, showCertUpload: !data.showCertUpload})}
                                                        className="px-3 py-1 bg-proxmox-card border border-proxmox-border rounded text-gray-300 text-sm hover:text-white hover:border-proxmox-orange"
                                                    >
                                                        {data.showCertUpload ? t('cancel') : (t('uploadCustomCert') || 'Upload Custom Certificate')}
                                                    </button>
                                                </div>
                                                
                                                {/* Current Certificates */}
                                                <div className="space-y-2 mb-4">
                                                    {(data.certificates||[]).length > 0 ? (data.certificates||[]).map((c, i) => (
                                                        <div key={i} className="flex justify-between items-center py-3 px-4 bg-proxmox-card rounded-lg">
                                                            <div>
                                                                <div className="text-white font-medium">{c.filename || 'Certificate'}</div>
                                                                <div className="text-xs text-gray-500">{c.subject || 'N/A'}</div>
                                                                <div className="text-xs text-gray-500">{t('issuer') || 'Issuer'}: {c.issuer || 'N/A'}</div>
                                                            </div>
                                                            <div className="text-right">
                                                                <div className={`text-sm ${c.notafter && c.notafter * 1000 > Date.now() ? 'text-green-400' : 'text-red-400'}`}>
                                                                    {c.notafter ? new Date(c.notafter * 1000).toLocaleDateString() : 'N/A'}
                                                                </div>
                                                                <div className="text-xs text-gray-500">
                                                                    {c.notafter ? (c.notafter * 1000 > Date.now() ? (t('valid') || 'Valid') : (t('expired') || 'Expired')) : ''}
                                                                </div>
                                                            </div>
                                                        </div>
                                                    )) : <div className="text-gray-500 text-sm">{t('noCertificates') || 'No certificates found'}</div>}
                                                </div>

                                                {/* Certificate Upload Form */}
                                                {data.showCertUpload && (
                                                    <div className="mt-4 p-4 bg-proxmox-card rounded-lg border border-proxmox-border space-y-4">
                                                        <div>
                                                            <label className="block text-xs text-gray-400 mb-2">{t('certificate') || 'Certificate'} (PEM {t('format') || 'Format'})</label>
                                                            <textarea 
                                                                value={data.newCert || ''} 
                                                                onChange={(e) => setData({...data, newCert: e.target.value})}
                                                                placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                                                                rows={6}
                                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm font-mono resize-none"
                                                            />
                                                            <p className="text-xs text-gray-500 mt-1">{t('certChainHint') || 'Can contain multiple certificates (chain)'}</p>
                                                        </div>
                                                        <div>
                                                            <label className="block text-xs text-gray-400 mb-2">{t('privateKey') || 'Private Key'} (PEM {t('format') || 'Format'})</label>
                                                            <textarea 
                                                                value={data.newKey || ''} 
                                                                onChange={(e) => setData({...data, newKey: e.target.value})}
                                                                placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                                                                rows={6}
                                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm font-mono resize-none"
                                                            />
                                                        </div>
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm text-gray-300">
                                                                <input type="checkbox" checked={data.certRestart !== false} onChange={(e) => setData({...data, certRestart: e.target.checked})} className="rounded" />
                                                                {t('restartPveproxyAfterUpload') || 'Restart pveproxy after upload'}
                                                            </label>
                                                        </div>
                                                        <div className="flex gap-3">
                                                            <button
                                                                onClick={async () => {
                                                                    if (!data.newCert || !data.newKey) {
                                                                        addToast(t('certAndKeyRequired') || 'Certificate and key required', 'error');
                                                                        return;
                                                                    }
                                                                    try {
                                                                        const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/certificates/custom`, {
                                                                            method: 'POST',
                                                                            credentials: 'include',
                                                                            headers: { 'Content-Type': 'application/json' },
                                                                            body: JSON.stringify({
                                                                                certificates: data.newCert,
                                                                                key: data.newKey,
                                                                                restart: data.certRestart !== false,
                                                                                force: true
                                                                            })
                                                                        });
                                                                        if (res.ok) {
                                                                            addToast(t('certUploaded') || 'Certificate uploaded!');
                                                                            setData({...data, newCert: '', newKey: '', showCertUpload: false});
                                                                            loadTabData('system');
                                                                        } else {
                                                                            const err = await res.json();
                                                                            addToast(err.error || t('uploadFailed') || 'Upload failed', 'error');
                                                                        }
                                                                    } catch (e) {
                                                                        addToast(t('connectionError'), 'error');
                                                                    }
                                                                }}
                                                                className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange rounded-lg text-white text-sm hover:bg-orange-600"
                                                            >
                                                                <Icons.Shield />
                                                                {t('uploadCertificate') || 'Upload Certificate'}
                                                            </button>
                                                            <button
                                                                onClick={async () => {
                                                                    if (!confirm(t('deleteCertConfirm') || 'Delete custom certificate and revert to self-signed?')) return;
                                                                    try {
                                                                        const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/certificates/custom?restart=true`, {
                                                                            method: 'DELETE',
                                                                            credentials: 'include',
                                                                        });
                                                                        if (res.ok) {
                                                                            addToast(t('certDeleted') || 'Certificate deleted');
                                                                            loadTabData('system');
                                                                        } else {
                                                                            const err = await res.json();
                                                                            addToast(err.error || t('deleteFailed'), 'error');
                                                                        }
                                                                    } catch (e) {
                                                                        addToast(t('connectionError'), 'error');
                                                                    }
                                                                }}
                                                                className="px-4 py-2 bg-red-500/20 border border-red-500/50 rounded-lg text-red-400 text-sm hover:bg-red-500/30"
                                                            >
                                                                {t('deleteCustomCert') || 'Delete Custom Cert'}
                                                            </button>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>

                                            {/* Syslog */}
                                            <div className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                <div className="flex justify-between items-center mb-3">
                                                    <h4 className="font-medium text-white">{t('syslogLatest') || 'Syslog (latest entries)'}</h4>
                                                    <button 
                                                        onClick={() => loadTabData('system')}
                                                        className="p-1.5 rounded hover:bg-proxmox-hover text-gray-400 hover:text-white"
                                                        title={t('refresh') || 'Refresh'}
                                                    >
                                                        <Icons.RefreshCw />
                                                    </button>
                                                </div>
                                                <div className="max-h-64 overflow-y-auto bg-black/50 rounded p-3">
                                                    {(data.syslog||[]).length > 0 ? (
                                                        <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap leading-relaxed">{(data.syslog||[]).join('\n')}</pre>
                                                    ) : (
                                                        <div className="text-gray-500 text-sm">{t('noLogEntries') || 'No log entries'}</div>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {activeTab === 'disks' && (
                                        <div className="space-y-6">
                                            {/* Physical Disks with Actions */}
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                                    <h3 className="font-medium text-white flex items-center gap-2">
                                                        <Icons.HardDrive />
                                                        Physical Disks
                                                    </h3>
                                                    <button 
                                                        onClick={() => loadTabData('disks')}
                                                        className="p-2 hover:bg-proxmox-hover rounded-lg text-gray-400 hover:text-white"
                                                    >
                                                        <Icons.RefreshCw />
                                                    </button>
                                                </div>
                                                <div className="overflow-x-auto">
                                                    <table className="w-full">
                                                        <thead className="bg-proxmox-dark">
                                                            <tr>
                                                                <th className="text-left p-3 text-sm text-gray-400">Device</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">Model</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">Size</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">Type</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">Usage</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">Health</th>
                                                                <th className="text-left p-3 text-sm text-gray-400">Actions</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {(data.disks||[]).length > 0 ? (data.disks||[]).map((d, idx) => (
                                                                <tr key={d.devpath || idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                                    <td className="p-3">
                                                                        <span className="font-mono text-white">{d.devpath || 'Unknown'}</span>
                                                                        {d.serial && <div className="text-xs text-gray-500 font-mono">{d.serial}</div>}
                                                                    </td>
                                                                    <td className="p-3 text-gray-400 text-sm max-w-48 truncate">{d.model || 'Unknown'}</td>
                                                                    <td className="p-3 text-proxmox-orange font-medium">{formatBytes(d.size)}</td>
                                                                    <td className="p-3">
                                                                        <span className={`px-2 py-0.5 rounded text-xs ${
                                                                            d.type === 'ssd' ? 'bg-blue-500/20 text-blue-400' :
                                                                            d.type === 'nvme' ? 'bg-purple-500/20 text-purple-400' :
                                                                            'bg-gray-500/20 text-gray-400'
                                                                        }`}>
                                                                            {(d.type || 'hdd').toUpperCase()}
                                                                        </span>
                                                                    </td>
                                                                    <td className="p-3">
                                                                        {d.used === 'unused' || !d.used ? (
                                                                            <span className="text-green-400 text-sm">✓ Unused</span>
                                                                        ) : (
                                                                            <span className="text-yellow-400 text-sm">{d.used}</span>
                                                                        )}
                                                                    </td>
                                                                    <td className="p-3">
                                                                        <span className={`px-2 py-0.5 rounded text-xs ${
                                                                            d.health === 'PASSED' ? 'bg-green-500/20 text-green-400' :
                                                                            d.health === 'FAILED' ? 'bg-red-500/20 text-red-400' :
                                                                            'bg-gray-500/20 text-gray-400'
                                                                        }`}>
                                                                            {d.health || 'N/A'}
                                                                        </span>
                                                                    </td>
                                                                    <td className="p-3">
                                                                        <div className="flex gap-1">
                                                                            <button 
                                                                                onClick={async () => {
                                                                                    try {
                                                                                        const diskPath = (d.devpath || '').replace('/dev/', '');
                                                                                        const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/disks/${encodeURIComponent(diskPath)}/smart`, { credentials: 'include' });
                                                                                        if (res.ok) {
                                                                                            const smart = await res.json();
                                                                                            alert(`SMART Data for ${d.devpath}:\n\n${JSON.stringify(smart, null, 2)}`);
                                                                                        } else {
                                                                                            alert(t('smartNotAvailable'));
                                                                                        }
                                                                                    } catch(e) { alert(t('smartFetchError')); }
                                                                                }}
                                                                                className="p-1.5 hover:bg-blue-500/20 rounded text-gray-400 hover:text-blue-400"
                                                                                title="SMART Data"
                                                                            >
                                                                                <Icons.Activity />
                                                                            </button>
                                                                            {(d.used === 'unused' || !d.used) && (
                                                                                <>
                                                                                    <button 
                                                                                        onClick={async () => {
                                                                                            if (!confirm(`Initialize ${d.devpath} with GPT partition table?\n\nThis will ERASE all data on the disk!`)) return;
                                                                                            try {
                                                                                                const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/disks/initgpt`, {
                                                                                                    method: 'POST',
                                                                                                    credentials: 'include',
                                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                                    body: JSON.stringify({ disk: d.devpath })
                                                                                                });
                                                                                                if (res.ok) {
                                                                                                    addToast('GPT partition table initialized', 'success');
                                                                                                    loadTabData('disks');
                                                                                                } else {
                                                                                                    const err = await res.json();
                                                                                                    addToast(err.error || 'Failed to initialize', 'error');
                                                                                                }
                                                                                            } catch(e) { addToast('Error initializing disk', 'error'); }
                                                                                        }}
                                                                                        className="p-1.5 hover:bg-green-500/20 rounded text-gray-400 hover:text-green-400"
                                                                                        title="Initialize GPT"
                                                                                    >
                                                                                        <Icons.Plus />
                                                                                    </button>
                                                                                    <button 
                                                                                        onClick={async () => {
                                                                                            if (!confirm(`⚠️ DANGER: Wipe disk ${d.devpath}?\n\nThis will DESTROY ALL DATA on the disk!`)) return;
                                                                                            if (!confirm(`Are you ABSOLUTELY SURE?\n\nThis action cannot be undone!`)) return;
                                                                                            try {
                                                                                                const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/disks/wipe`, {
                                                                                                    method: 'POST',
                                                                                                    credentials: 'include',
                                                                                                    headers: { 'Content-Type': 'application/json' },
                                                                                                    body: JSON.stringify({ disk: d.devpath })
                                                                                                });
                                                                                                if(res.ok) {
                                                                                                    addToast('Disk wiped successfully', 'success');
                                                                                                    loadTabData('disks');
                                                                                                } else {
                                                                                                    const err = await res.json();
                                                                                                    addToast(err.error || 'Failed to wipe', 'error');
                                                                                                }
                                                                                            } catch(e) { addToast('Error wiping disk', 'error'); }
                                                                                        }}
                                                                                        className="p-1.5 hover:bg-red-500/20 rounded text-gray-400 hover:text-red-400"
                                                                                        title="Wipe Disk"
                                                                                    >
                                                                                        <Icons.Trash />
                                                                                    </button>
                                                                                </>
                                                                            )}
                                                                        </div>
                                                                    </td>
                                                                </tr>
                                                            )) : (
                                                                <tr><td colSpan="7" className="p-8 text-center text-gray-500">No physical disks found</td></tr>
                                                            )}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </div>

                                            {/* LVM Volume Groups */}
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                                    <h3 className="font-medium text-white flex items-center gap-2">
                                                        <Icons.Database />
                                                        LVM Volume Groups
                                                    </h3>
                                                    <button 
                                                        onClick={() => openDiskModal('lvm')}
                                                        className="px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                                    >
                                                        <Icons.Plus className="inline mr-1" /> Create LVM
                                                    </button>
                                                </div>
                                                <div className="p-4">
                                                    {(data.lvm||[]).length > 0 ? (
                                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                                            {data.lvm.map((v, idx) => (
                                                                <div key={v.vg || idx} className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                                    <div className="flex justify-between items-center mb-2">
                                                                        <span className="font-medium text-white">{v.vg || 'Unknown'}</span>
                                                                        <span className="text-proxmox-orange font-medium">{formatBytes(v.size)}</span>
                                                                    </div>
                                                                    {v.free && v.size && (
                                                                        <>
                                                                            <div className="h-2 bg-proxmox-darker rounded-full overflow-hidden">
                                                                                <div 
                                                                                    className="h-full bg-proxmox-orange rounded-full"
                                                                                    style={{ width: `${Math.round((1 - v.free/v.size) * 100)}%` }}
                                                                                />
                                                                            </div>
                                                                            <div className="text-xs text-gray-500 mt-1">
                                                                                {formatBytes(v.free)} free
                                                                            </div>
                                                                        </>
                                                                    )}
                                                                </div>
                                                            ))}
                                                        </div>
                                                    ) : <div className="text-gray-500 text-sm text-center py-4">No LVM Volume Groups</div>}
                                                </div>
                                            </div>

                                            {/* LVM-Thin Pools */}
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                                    <h3 className="font-medium text-white flex items-center gap-2">
                                                        <Icons.Database />
                                                        LVM-Thin Pools
                                                    </h3>
                                                    <button 
                                                        onClick={() => openDiskModal('lvmthin')}
                                                        className="px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                                    >
                                                        <Icons.Plus className="inline mr-1" /> Create LVM-Thin
                                                    </button>
                                                </div>
                                                <div className="p-4">
                                                    {(data.lvmthin||[]).length > 0 ? (
                                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                                            {data.lvmthin.map((p, idx) => (
                                                                <div key={p.lv || idx} className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                                    <div className="flex justify-between items-center mb-2">
                                                                        <span className="font-medium text-white">{p.lv || 'Unknown'}</span>
                                                                        <span className="text-proxmox-orange font-medium">{formatBytes(p.lv_size)}</span>
                                                                    </div>
                                                                    <div className="text-xs text-gray-500 mb-2">VG: {p.vg || '?'}</div>
                                                                    <div className="h-2 bg-proxmox-darker rounded-full overflow-hidden">
                                                                        <div 
                                                                            className={`h-full rounded-full ${(p.usage||0) > 80 ? 'bg-red-500' : (p.usage||0) > 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
                                                                            style={{ width: `${p.usage || 0}%` }}
                                                                        />
                                                                    </div>
                                                                    <div className="text-xs text-gray-500 mt-1">{p.usage || 0}% used</div>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    ) : <div className="text-gray-500 text-sm text-center py-4">No LVM-Thin Pools</div>}
                                                </div>
                                            </div>

                                            {/* ZFS Pools */}
                                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                <div className="p-4 border-b border-proxmox-border flex items-center justify-between">
                                                    <h3 className="font-medium text-white flex items-center gap-2">
                                                        <Icons.Database />
                                                        ZFS Pools
                                                    </h3>
                                                    <div className="flex gap-2">
                                                        <button 
                                                            onClick={() => openDiskModal('directory')}
                                                            className="px-3 py-1.5 bg-proxmox-dark hover:bg-proxmox-hover border border-proxmox-border rounded-lg text-sm"
                                                        >
                                                            <Icons.Folder className="inline mr-1" /> Directory
                                                        </button>
                                                        <button 
                                                            onClick={() => openDiskModal('zfs')}
                                                            className="px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm"
                                                        >
                                                            <Icons.Plus className="inline mr-1" /> Create ZFS
                                                        </button>
                                                    </div>
                                                </div>
                                                <div className="p-4">
                                                    {(data.zfs||[]).length > 0 ? (
                                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                                            {data.zfs.map((z, idx) => (
                                                                <div key={z.name || idx} className="p-4 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                                    <div className="flex justify-between items-center mb-2">
                                                                        <div className="flex items-center gap-2">
                                                                            <span className="font-medium text-white">{z.name || 'Unknown'}</span>
                                                                            <span className={`text-xs px-2 py-0.5 rounded ${
                                                                                z.health === 'ONLINE' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                                                                            }`}>
                                                                                {z.health || 'N/A'}
                                                                            </span>
                                                                        </div>
                                                                        <span className="text-proxmox-orange font-medium">{formatBytes(z.size)}</span>
                                                                    </div>
                                                                    {z.alloc && z.size && (
                                                                        <>
                                                                            <div className="h-2 bg-proxmox-darker rounded-full overflow-hidden">
                                                                                <div 
                                                                                    className="h-full bg-blue-500 rounded-full"
                                                                                    style={{ width: `${Math.round((z.alloc/z.size) * 100)}%` }}
                                                                                />
                                                                            </div>
                                                                            <div className="text-xs text-gray-500 mt-1">
                                                                                {formatBytes(z.free || (z.size - z.alloc))} free
                                                                            </div>
                                                                        </>
                                                                    )}
                                                                </div>
                                                            ))}
                                                        </div>
                                                    ) : <div className="text-gray-500 text-sm text-center py-4">No ZFS Pools</div>}
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* APT Repos tab */}
                                    {activeTab === 'repos' && (
                                        <div className="space-y-4">
                                            <div className="flex items-center justify-between">
                                                <h3 className="text-lg font-medium text-white flex items-center gap-2">
                                                    <Icons.Package className="w-5 h-5 text-proxmox-orange" />
                                                    APT {t('repositories') || 'Repositories'}
                                                </h3>
                                                <button
                                                    onClick={async () => {
                                                        try {
                                                            const r = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/repos/refresh`, {
                                                                method: 'POST',
                                                                credentials: 'include',
                                                                headers: authHeaders
                                                            });
                                                            if (r.ok) {
                                                                addToast(t('packageListRefreshStarted') || 'Package list refresh started', 'success');
                                                            } else {
                                                                addToast(t('error') || 'Error', 'error');
                                                            }
                                                        } catch (e) {
                                                            addToast(t('error') || 'Error', 'error');
                                                        }
                                                    }}
                                                    className="px-3 py-1.5 bg-proxmox-orange/20 hover:bg-proxmox-orange/30 text-proxmox-orange rounded-lg text-sm flex items-center gap-2"
                                                >
                                                    <Icons.RefreshCw className="w-4 h-4" />
                                                    apt update
                                                </button>
                                            </div>

                                            {/* Info Box */}
                                            <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg text-sm">
                                                <p className="text-gray-300">
                                                    {t('repoInfo') || 'Manage APT repositories for this node. Enable/disable repositories to control which packages are available.'}
                                                </p>
                                            </div>

                                            {/* Proxmox Source Format Notice */}
                                            <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-sm">
                                                <p className="text-yellow-400 flex items-center gap-2">
                                                    <Icons.AlertTriangle className="w-4 h-4 flex-shrink-0" />
                                                    {t('repoProxmoxNotice') || "Note: Due to Proxmox's switch to a new source format, the display may currently be inaccurate. We're working on it."}
                                                </p>
                                            </div>

                                            {/* Repository List */}
                                            {loading ? (
                                                <div className="text-center py-8 text-gray-500">
                                                    <Icons.RotateCw className="w-6 h-6 animate-spin mx-auto mb-2" />
                                                    {t('loading')}...
                                                </div>
                                            ) : (data.repos || []).length > 0 ? (
                                                <div className="space-y-3">
                                                    {(data.repos || []).map(repo => (
                                                        <div 
                                                            key={repo.id}
                                                            className={`p-4 rounded-lg border transition-all ${
                                                                repo.enabled 
                                                                    ? 'bg-green-500/5 border-green-500/30' 
                                                                    : 'bg-proxmox-dark border-proxmox-border'
                                                            }`}
                                                        >
                                                            <div className="flex items-center justify-between">
                                                                <div className="flex items-center gap-3">
                                                                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                                                                        repo.enabled ? 'bg-green-500/20' : 'bg-gray-500/20'
                                                                    }`}>
                                                                        {repo.requires_subscription ? (
                                                                            <Icons.Shield className={repo.enabled ? 'text-green-400' : 'text-gray-500'} />
                                                                        ) : (
                                                                            <Icons.Package className={repo.enabled ? 'text-green-400' : 'text-gray-500'} />
                                                                        )}
                                                                    </div>
                                                                    <div>
                                                                        <div className="flex items-center gap-2">
                                                                            <h4 className="font-medium text-white">{repo.name}</h4>
                                                                            {repo.is_other && (
                                                                                <span className="text-xs px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400">
                                                                                    {t('detected') || 'Detected'}
                                                                                </span>
                                                                            )}
                                                                        </div>
                                                                        <p className="text-xs text-gray-500">{repo.description}</p>
                                                                        {repo.requires_subscription && (
                                                                            <span className="inline-block mt-1 text-xs px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-400">
                                                                                {t('requiresSubscription') || 'Requires Subscription'}
                                                                            </span>
                                                                        )}
                                                                        {repo.uri && (
                                                                            <p className="text-xs text-gray-600 mt-1 font-mono truncate max-w-xs">{repo.uri}</p>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                                <div className="flex items-center gap-3">
                                                                    <span className={`text-xs px-2 py-1 rounded ${
                                                                        repo.enabled 
                                                                            ? 'bg-green-500/20 text-green-400' 
                                                                            : 'bg-gray-500/20 text-gray-400'
                                                                    }`}>
                                                                        {repo.enabled ? (t('enabled') || 'Enabled') : (t('disabled') || 'Disabled')}
                                                                    </span>
                                                                    {repo.exists && (
                                                                        <button
                                                                            onClick={async () => {
                                                                                try {
                                                                                    // For "other" repos, include file and index
                                                                                    const bodyData = { enabled: !repo.enabled };
                                                                                    if (repo.is_other) {
                                                                                        bodyData.file = repo.file;
                                                                                        bodyData.index = repo.index;
                                                                                        bodyData.name = repo.name;
                                                                                    }
                                                                                    const r = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/repos/${repo.id}`, {
                                                                                        method: 'PUT',
                                                                                        credentials: 'include',
                                                                                        headers: { 'Content-Type': 'application/json', ...authHeaders },
                                                                                        body: JSON.stringify(bodyData)
                                                                                    });
                                                                                    if (r.ok) {
                                                                                        addToast(`${repo.name} ${!repo.enabled ? 'enabled' : 'disabled'}`, 'success');
                                                                                        loadTabData('repos');
                                                                                    } else {
                                                                                        const err = await r.json();
                                                                                        addToast(err.error || t('error'), 'error');
                                                                                    }
                                                                                } catch (e) {
                                                                                    addToast(t('error') || 'Error', 'error');
                                                                                }
                                                                            }}
                                                                            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                                                                                repo.enabled
                                                                                    ? 'bg-red-500/20 hover:bg-red-500/30 text-red-400'
                                                                                    : 'bg-green-500/20 hover:bg-green-500/30 text-green-400'
                                                                            }`}
                                                                        >
                                                                            {repo.enabled ? (t('disable') || 'Disable') : (t('enable') || 'Enable')}
                                                                        </button>
                                                                    )}
                                                                    {!repo.exists && (
                                                                        <span className="text-xs text-gray-500">{t('notConfigured') || 'Not configured'}</span>
                                                                    )}
                                                                </div>
                                                            </div>
                                                            {repo.file && (
                                                                <div className="mt-2 text-xs text-gray-500 font-mono">
                                                                    {repo.file}
                                                                </div>
                                                            )}
                                                        </div>
                                                    ))}
                                                </div>
                                            ) : (
                                                <div className="text-center py-8 text-gray-500">
                                                    {t('noReposFound') || 'No repositories found'}
                                                </div>
                                            )}

                                            {/* Warning */}
                                            <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                                <div className="flex items-start gap-2">
                                                    <Icons.AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                                                    <div className="text-sm text-yellow-200">
                                                        <strong>{t('warning') || 'Warning'}:</strong> {t('repoWarning') || 'Mixing enterprise and no-subscription repositories is not recommended. After changing repositories, run "apt update" to refresh the package list.'}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {activeTab === 'tasks' && (
                                        <div className="space-y-2">
                                            {(data.tasks||[]).length > 0 ? (data.tasks||[]).map((t, idx) => (
                                                <div key={t.upid || idx} className="p-3 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                    <div className="flex justify-between items-center">
                                                        <div>
                                                            <span className="text-white">{t.type || 'Unknown'}</span>
                                                            <span className={`ml-2 text-xs px-2 py-0.5 rounded ${t.status==='OK'?'text-green-400 bg-green-500/10':t.status?'text-red-400 bg-red-500/10':'text-yellow-400 bg-yellow-500/10'}`}>
                                                                {t.status || 'running'}
                                                            </span>
                                                        </div>
                                                        <span className="text-xs text-gray-500">{t.starttime ? new Date(t.starttime*1000).toLocaleString() : 'N/A'}</span>
                                                    </div>
                                                    <div className="text-xs text-gray-500 mt-1">{t.user || 'unknown'} - {t.id || 'N/A'}</div>
                                                </div>
                                            )) : <div className="text-center py-8 text-gray-500">{t('noTasks') || 'No tasks'}</div>}
                                        </div>
                                    )}

                                    {activeTab === 'subscription' && (
                                        <div className="space-y-6">
                                            <div className="p-6 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                <div className="flex items-center justify-between mb-4">
                                                    <h3 className="font-medium text-white">{t('subscriptionStatus')}</h3>
                                                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                                                        data.subscription?.status === 'Active' || data.subscription?.status === 'active' 
                                                            ? 'bg-green-500/20 text-green-400' 
                                                            : 'bg-yellow-500/20 text-yellow-400'
                                                    }`}>
                                                        {data.subscription?.status === 'Active' || data.subscription?.status === 'active' ? t('licensed') : t('notLicensed')}
                                                    </span>
                                                </div>
                                                
                                                {(data.subscription?.status === 'Active' || data.subscription?.status === 'active') ? (
                                                    <div className="space-y-3 text-sm">
                                                        <div className="flex justify-between py-2 border-b border-proxmox-border">
                                                            <span className="text-gray-400">{t('product')}</span>
                                                            <span className="text-white">{data.subscription?.productname || 'Proxmox VE Subscription'}</span>
                                                        </div>
                                                        <div className="flex justify-between py-2 border-b border-proxmox-border">
                                                            <span className="text-gray-400">{t('licenseKey')}</span>
                                                            <span className="text-white font-mono">{data.subscription?.key || 'N/A'}</span>
                                                        </div>
                                                        <div className="flex justify-between py-2 border-b border-proxmox-border">
                                                            <span className="text-gray-400">Server ID</span>
                                                            <span className="text-white font-mono">{data.subscription?.serverid || 'N/A'}</span>
                                                        </div>
                                                        <div className="flex justify-between py-2 border-b border-proxmox-border">
                                                            <span className="text-gray-400">{t('validUntil')}</span>
                                                            <span className="text-white">{data.subscription?.nextduedate || 'N/A'}</span>
                                                        </div>
                                                        <div className="flex justify-between py-2">
                                                            <span className="text-gray-400">{t('supportLevel')}</span>
                                                            <span className="text-white">{data.subscription?.level || 'N/A'}</span>
                                                        </div>
                                                    </div>
                                                ) : (
                                                    <div className="space-y-4">
                                                        <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                                            <div className="flex items-start gap-3">
                                                                <Icons.AlertTriangle />
                                                                <div>
                                                                    <div className="text-yellow-400 font-medium">{t('noActiveSubscription')}</div>
                                                                    <div className="text-sm text-gray-400 mt-1">
                                                                        {t('noSubscriptionDesc')}
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        </div>
                                                        
                                                        {data.subscription?.serverid && (
                                                            <div className="text-sm">
                                                                <span className="text-gray-400">Server ID: </span>
                                                                <span className="text-white font-mono">{data.subscription.serverid}</span>
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                            </div>

                                            {/* License Key Input */}
                                            <div className="p-6 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                                <h4 className="font-medium text-white mb-4">{t('enterLicenseKey')}</h4>
                                                <div className="space-y-4">
                                                    <div>
                                                        <label className="block text-xs text-gray-400 mb-2">{t('subscriptionKey')}</label>
                                                        <input 
                                                            type="text" 
                                                            value={data.newLicenseKey || ''} 
                                                            onChange={(e) => setData({...data, newLicenseKey: e.target.value})}
                                                            placeholder="pve1c-xxxxxxxxxx"
                                                            className="w-full px-4 py-3 bg-proxmox-card border border-proxmox-border rounded-lg text-white font-mono focus:outline-none focus:border-proxmox-orange"
                                                        />
                                                        <p className="text-xs text-gray-500 mt-2">
                                                            Format: pve1c-xxxxxxxxxx, pve2c-xxxxxxxxxx, pve4c-xxxxxxxxxx, etc.
                                                        </p>
                                                    </div>
                                                    <div className="flex gap-3">
                                                        <button
                                                            onClick={async () => {
                                                                if(!data.newLicenseKey) {
                                                                    addToast(t('pleaseEnterLicenseKey'), 'error');
                                                                    return;
                                                                }
                                                                try {
                                                                    const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/subscription`, {
                                                                        method: 'PUT',
                                                                        credentials: 'include',
                                                                        headers: { 'Content-Type': 'application/json' },
                                                                        body: JSON.stringify({ key: data.newLicenseKey })
                                                                    });
                                                                    if(res.ok) {
                                                                        addToast(t('licenseActivated'));
                                                                        setData({...data, newLicenseKey: ''});
                                                                        loadTabData('subscription');
                                                                    } else {
                                                                        const err = await res.json();
                                                                        addToast(err.error || t('activationFailed'), 'error');
                                                                    }
                                                                } catch (e) {
                                                                    addToast(t('connectionError'), 'error');
                                                                }
                                                            }}
                                                            disabled={!data.newLicenseKey}
                                                            className="flex items-center gap-2 px-4 py-2 bg-proxmox-orange rounded-lg text-white font-medium hover:bg-orange-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                                        >
                                                            <Icons.Shield />
                                                            {t('activateLicense')}
                                                        </button>
                                                        <button
                                                            onClick={() => loadTabData('subscription')}
                                                            className="flex items-center gap-2 px-4 py-2 bg-proxmox-card border border-proxmox-border rounded-lg text-gray-300 hover:text-white transition-colors"
                                                        >
                                                            <Icons.RefreshCw />
                                                            {t('refreshStatus')}
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Info Box */}
                                            <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                                                <div className="flex items-start gap-3">
                                                    <Icons.Info />
                                                    <div className="text-sm text-gray-300">
                                                        <p className="mb-2">{t('subscriptionBenefits')}:</p>
                                                        <ul className="list-disc list-inside space-y-1 text-gray-400">
                                                            <li>{t('subscriptionBenefit1')}</li>
                                                            <li>{t('subscriptionBenefit2')}</li>
                                                            <li>{t('subscriptionBenefit3')}</li>
                                                        </ul>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {activeTab === 'ceph' && (
                                        <div className="space-y-6">
                                            {loading ? (
                                                <div className="flex items-center justify-center py-12">
                                                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-proxmox-orange"></div>
                                                </div>
                                            ) : !data.ceph?.available ? (
                                                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-8 text-center">
                                                    <Icons.Database className="w-12 h-12 mx-auto text-gray-600 mb-4" />
                                                    <h3 className="text-lg font-semibold mb-2">{t('cephNotInstalled') || 'Ceph Not Installed'}</h3>
                                                    <p className="text-gray-400 mb-4">{t('cephNotInstalledOnNode') || 'Ceph is not configured on this node.'}</p>
                                                    <button
                                                        onClick={async () => {
                                                            if (!confirm('Initialize Ceph on this node? This will install and configure Ceph.')) return;
                                                            try {
                                                                const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/init`, {
                                                                    method: 'POST',
                                                                    credentials: 'include',
                                                                    headers: { 'Content-Type': 'application/json', ...authHeaders }
                                                                });
                                                                if (res.ok) {
                                                                    addToast('Ceph initialization started', 'success');
                                                                    loadTabData('ceph');
                                                                } else {
                                                                    const err = await res.json().catch(() => ({}));
                                                                    addToast(err.error || 'Failed to initialize Ceph', 'error');
                                                                }
                                                            } catch (e) {
                                                                addToast('Connection error', 'error');
                                                            }
                                                        }}
                                                        className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-white font-medium transition-colors"
                                                    >
                                                        {t('cephInit') || 'Initialize Ceph'}
                                                    </button>
                                                </div>
                                            ) : (
                                                <>
                                                    {/* Ceph Status Overview */}
                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-6">
                                                        <div className="flex items-center justify-between mb-4">
                                                            <h3 className="font-semibold flex items-center gap-2">
                                                                <Icons.Activity />
                                                                {t('cephStatus') || 'Ceph Status'}
                                                            </h3>
                                                            <div className="flex gap-2">
                                                                {['start', 'stop', 'restart'].map(action => (
                                                                    <button
                                                                        key={action}
                                                                        onClick={async () => {
                                                                            if (!confirm(`${action.charAt(0).toUpperCase() + action.slice(1)} Ceph services on ${node}?`)) return;
                                                                            try {
                                                                                const res = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/${action}`, {
                                                                                    method: 'POST',
                                                                                    credentials: 'include',
                                                                                    headers: authHeaders
                                                                                });
                                                                                addToast(res.ok ? `Ceph ${action} initiated` : `Failed to ${action}`, res.ok ? 'success' : 'error');
                                                                                if (res.ok) setTimeout(() => loadTabData('ceph'), 2000);
                                                                            } catch (e) { addToast('Error', 'error'); }
                                                                        }}
                                                                        className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                                                                            action === 'stop' ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30' :
                                                                            action === 'restart' ? 'bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30' :
                                                                            'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                                                                        }`}
                                                                    >
                                                                        {action.charAt(0).toUpperCase() + action.slice(1)}
                                                                    </button>
                                                                ))}
                                                            </div>
                                                        </div>
                                                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                                            <div className="bg-proxmox-dark rounded-lg p-4">
                                                                <div className="text-sm text-gray-400 mb-1">{t('health') || 'Health'}</div>
                                                                <div className={`text-xl font-bold ${
                                                                    data.ceph?.status?.health?.status === 'HEALTH_OK' ? 'text-green-400' :
                                                                    data.ceph?.status?.health?.status === 'HEALTH_WARN' ? 'text-yellow-400' :
                                                                    'text-red-400'
                                                                }`}>
                                                                    {data.ceph?.status?.health?.status || 'Unknown'}
                                                                </div>
                                                            </div>
                                                            <div className="bg-proxmox-dark rounded-lg p-4">
                                                                <div className="text-sm text-gray-400 mb-1">OSDs</div>
                                                                <div className="text-xl font-bold text-blue-400">{(data.ceph?.osd || []).length}</div>
                                                                <div className="text-xs text-gray-400">
                                                                    {(data.ceph?.osd || []).filter(o => o.status === 'up').length} up, {(data.ceph?.osd || []).filter(o => o.in).length} in
                                                                </div>
                                                            </div>
                                                            <div className="bg-proxmox-dark rounded-lg p-4">
                                                                <div className="text-sm text-gray-400 mb-1">{t('cephMons') || 'Monitors'}</div>
                                                                <div className="text-xl font-bold text-purple-400">{(data.ceph?.mon || []).length}</div>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    {/* OSDs on this node */}
                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                        <div className="p-4 border-b border-proxmox-border">
                                                            <h3 className="font-semibold">OSDs ({(data.ceph?.osd || []).length})</h3>
                                                        </div>
                                                        <div className="overflow-x-auto">
                                                            <table className="w-full">
                                                                <thead className="bg-proxmox-dark">
                                                                    <tr>
                                                                        <th className="text-left p-3 text-sm text-gray-400">ID</th>
                                                                        <th className="text-left p-3 text-sm text-gray-400">{t('name') || 'Name'}</th>
                                                                        <th className="text-left p-3 text-sm text-gray-400">{t('status')}</th>
                                                                        <th className="text-left p-3 text-sm text-gray-400">In/Out</th>
                                                                        <th className="text-left p-3 text-sm text-gray-400">Class</th>
                                                                        <th className="text-left p-3 text-sm text-gray-400">{t('actions')}</th>
                                                                    </tr>
                                                                </thead>
                                                                <tbody>
                                                                    {(!data.ceph?.osd || data.ceph.osd.length === 0) ? (
                                                                        <tr><td colSpan="6" className="p-8 text-center text-gray-500">No OSDs on this node</td></tr>
                                                                    ) : data.ceph.osd.map((osd) => (
                                                                        <tr key={osd.id} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                                            <td className="p-3">{osd.id}</td>
                                                                            <td className="p-3 font-medium">{osd.name || `osd.${osd.id}`}</td>
                                                                            <td className="p-3">
                                                                                <span className={`px-2 py-0.5 rounded text-xs ${
                                                                                    osd.status === 'up' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                                                                                }`}>{osd.status || 'unknown'}</span>
                                                                            </td>
                                                                            <td className="p-3">
                                                                                <span className={`px-2 py-0.5 rounded text-xs ${
                                                                                    osd.in ? 'bg-blue-500/20 text-blue-400' : 'bg-yellow-500/20 text-yellow-400'
                                                                                }`}>{osd.in ? 'In' : 'Out'}</span>
                                                                            </td>
                                                                            <td className="p-3 text-gray-300">{osd.device_class || osd.class || '-'}</td>
                                                                            <td className="p-3">
                                                                                <div className="flex gap-1">
                                                                                    <button
                                                                                        onClick={async () => {
                                                                                            const action = osd.in ? 'out' : 'in';
                                                                                            if (!confirm(`Mark OSD ${osd.id} as ${action.toUpperCase()}?`)) return;
                                                                                            try {
                                                                                                await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/osd/${osd.id}/${action}`, {
                                                                                                    method: 'POST', credentials: 'include', headers: authHeaders
                                                                                                });
                                                                                                loadTabData('ceph');
                                                                                            } catch (e) {}
                                                                                        }}
                                                                                        className="px-2 py-1 text-xs bg-proxmox-dark hover:bg-proxmox-hover rounded transition-colors"
                                                                                    >
                                                                                        {osd.in ? 'Out' : 'In'}
                                                                                    </button>
                                                                                    <button
                                                                                        onClick={async () => {
                                                                                            try {
                                                                                                await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/osd/${osd.id}/scrub`, {
                                                                                                    method: 'POST', credentials: 'include', headers: authHeaders
                                                                                                });
                                                                                                addToast('Scrub started', 'success');
                                                                                            } catch (e) {}
                                                                                        }}
                                                                                        className="px-2 py-1 text-xs bg-proxmox-dark hover:bg-proxmox-hover rounded transition-colors"
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

                                                    {/* Monitors */}
                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                        <div className="p-4 border-b border-proxmox-border">
                                                            <h3 className="font-semibold">{t('cephMons') || 'Monitors'} ({(data.ceph?.mon || []).length})</h3>
                                                        </div>
                                                        <div className="divide-y divide-proxmox-border">
                                                            {(data.ceph?.mon || []).map((mon, idx) => (
                                                                <div key={idx} className="p-4 flex justify-between items-center">
                                                                    <div>
                                                                        <span className="font-medium">{mon.name}</span>
                                                                        {mon.addr && <span className="text-gray-400 ml-2 font-mono text-xs">{mon.addr}</span>}
                                                                    </div>
                                                                    <span className={`px-2 py-0.5 rounded text-xs ${
                                                                        mon.quorum !== false ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                                                                    }`}>
                                                                        {mon.quorum !== false ? 'In Quorum' : 'Not in Quorum'}
                                                                    </span>
                                                                </div>
                                                            ))}
                                                            {(!data.ceph?.mon || data.ceph.mon.length === 0) && (
                                                                <div className="p-8 text-center text-gray-500">No monitors</div>
                                                            )}
                                                        </div>
                                                    </div>

                                                    {/* Pools */}
                                                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-hidden">
                                                        <div className="p-4 border-b border-proxmox-border">
                                                            <h3 className="font-semibold">{t('cephPools') || 'Pools'} ({(data.ceph?.pools || []).length})</h3>
                                                        </div>
                                                        <div className="overflow-x-auto">
                                                            <table className="w-full">
                                                                <thead className="bg-proxmox-dark">
                                                                    <tr>
                                                                        <th className="text-left p-3 text-sm text-gray-400">{t('name')}</th>
                                                                        <th className="text-left p-3 text-sm text-gray-400">Size</th>
                                                                        <th className="text-left p-3 text-sm text-gray-400">PGs</th>
                                                                    </tr>
                                                                </thead>
                                                                <tbody>
                                                                    {(!data.ceph?.pools || data.ceph.pools.length === 0) ? (
                                                                        <tr><td colSpan="3" className="p-8 text-center text-gray-500">No pools</td></tr>
                                                                    ) : data.ceph.pools.map((pool, idx) => (
                                                                        <tr key={idx} className="border-t border-proxmox-border hover:bg-proxmox-dark/50">
                                                                            <td className="p-3 font-medium">{pool.pool_name || pool.name}</td>
                                                                            <td className="p-3 text-gray-300">{pool.size || '-'}</td>
                                                                            <td className="p-3 text-gray-300">{pool.pg_num || '-'}</td>
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                        </div>
                                                    </div>
                                                </>
                                            )}
                                        </div>
                                    )}
                                </>
                            )}
                        </div>
                    </div>

                    {/* Fullscreen Shell Modal */}
                    {data.shellFullscreen && (
                        <div className="fixed inset-0 z-[70] bg-black flex flex-col">
                            <div className="flex items-center justify-between px-4 py-2 bg-proxmox-dark border-b border-proxmox-border">
                                <div className="flex items-center gap-3">
                                    <Icons.Terminal />
                                    <span className="text-white font-medium">{node} - Shell</span>
                                </div>
                                <button
                                    onClick={() => setData({...data, shellFullscreen: false})}
                                    className="p-2 rounded-lg hover:bg-red-500/20 text-gray-400 hover:text-red-400"
                                >
                                    <Icons.X />
                                </button>
                            </div>
                            <div className="flex-1">
                                <NodeShellTerminal 
                                    node={node} 
                                    clusterId={clusterId} 
                                    addToast={addToast}
                                />
                            </div>
                        </div>
                    )}
                </div>
            );
        }

        // Console Modal Component with noVNC
        // NS: Getting noVNC to work in a React component was... interesting
        // The cleanup logic is important - otherwise you get zombie connections
        function ConsoleModal({ vm, consoleInfo, clusterId, onClose }) {
            const { t } = useTranslation();
            const canvasRef = useRef(null);
            const [isFullscreen, setIsFullscreen] = useState(false);
            const [connectionStatus, setConnectionStatus] = useState('connecting');
            const [vncPort, setVncPort] = useState(null);
            const [rfb, setRfb] = useState(null);
            const rfbRef = useRef(null);
            const containerRef = useRef(null);
            const { getAuthHeaders, sessionId } = useAuth();

            useEffect(() => {
                if(!consoleInfo || !canvasRef.current) return;

                let cancelled = false;
                
                const startVNC = async () => {
                    try {
                        setConnectionStatus('connecting');
                        console.log('VNC: Starting connection...');
                        
                        // Get VNC ticket from backend
                        console.log('VNC: Getting ticket...');
                        const ticketResponse = await fetch(
                            `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/console`,
                            { headers: getAuthHeaders() }
                        );
                        
                        if(!ticketResponse.ok) {
                            console.error('VNC: Failed to get ticket');
                            setConnectionStatus('error');
                            return;
                        }
                        
                        const ticketData = await ticketResponse.json();
                        if(!ticketData.success) {
                            console.error('VNC: Ticket error:', ticketData.error);
                            setConnectionStatus('error');
                            return;
                        }
                        
                        const vncPassword = ticketData.ticket;
                        console.log('VNC: Got ticket');
                        
                        if(cancelled) return;
                        
                        // Build WebSocket URL - VNC runs on main port + 1
                        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                        const mainPort = parseInt(window.location.port) || (window.location.protocol === 'https:' ? 443 : 80);
                        const vncPortNum = mainPort + 1;
                        setVncPort(vncPortNum);
                        const wsUrl = `${wsProtocol}//${window.location.hostname}:${vncPortNum}/api/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/vncwebsocket?session=${encodeURIComponent(sessionId)}`;
                        
                        console.log('VNC WebSocket URL:', wsUrl);
                        
                        // Load noVNC - try local first (if downloaded), then CDN
                        if(!window.RFB) {
                            console.log('VNC: Loading noVNC...');
                            await new Promise((resolve, reject) => {
                                const script = document.createElement('script');
                                script.type = 'module';
                                // NS: local path works if --download-static was run
                                const localPath = '/static/js/novnc/rfb.min.js';
                                const cdnPath = 'https://cdn.jsdelivr.net/npm/@novnc/novnc@1.4.0/core/rfb.js';
                                script.textContent = `
                                    let RFB;
                                    try {
                                        // Try local bundled version first
                                        const resp = await fetch('${localPath}', {method: 'HEAD'});
                                        if (resp.ok) {
                                            RFB = (await import('${localPath}')).default;
                                            console.log('VNC: loaded from local');
                                        } else {
                                            throw new Error('local not found');
                                        }
                                    } catch(e) {
                                        // Fallback to CDN
                                        RFB = (await import('${cdnPath}')).default;
                                        console.log('VNC: loaded from CDN');
                                    }
                                    if (RFB) {
                                        window.RFB = RFB;
                                        window.dispatchEvent(new CustomEvent('novnc-loaded'));
                                    } else {
                                        window.dispatchEvent(new CustomEvent('novnc-failed'));
                                    }
                                `;
                                
                                const onLoaded = () => {
                                    window.removeEventListener('novnc-loaded', onLoaded);
                                    window.removeEventListener('novnc-failed', onFailed);
                                    console.log('VNC: noVNC ready');
                                    resolve();
                                };
                                const onFailed = () => {
                                    window.removeEventListener('novnc-loaded', onLoaded);
                                    window.removeEventListener('novnc-failed', onFailed);
                                    reject(new Error('Failed to load noVNC'));
                                };
                                
                                window.addEventListener('novnc-loaded', onLoaded);
                                window.addEventListener('novnc-failed', onFailed);
                                document.head.appendChild(script);
                                
                                setTimeout(() => {
                                    if(!window.RFB) {
                                        window.removeEventListener('novnc-loaded', onLoaded);
                                        window.removeEventListener('novnc-failed', onFailed);
                                        reject(new Error('noVNC load timeout'));
                                    }
                                }, 10000);
                            });
                        }
                        
                        if(cancelled || !window.RFB) {
                            setConnectionStatus('load_error');
                            return;
                        }
                        
                        console.log('VNC: Connecting to', wsUrl);
                        
                        // Create RFB with credentials
                        const rfbInstance = new window.RFB(canvasRef.current, wsUrl, {
                            credentials: { password: vncPassword }
                        });
                        rfbInstance.scaleViewport = true;
                        rfbInstance.resizeSession = true;

                        rfbInstance.addEventListener('connect', () => {
                            console.log('VNC: Connected!');
                            setConnectionStatus('connected');
                        });

                        rfbInstance.addEventListener('disconnect', (e) => {
                            console.log('VNC: Disconnected', e.detail);
                            setConnectionStatus(e.detail.clean ? 'disconnected' : 'error');
                        });

                        rfbInstance.addEventListener('securityfailure', (e) => {
                            console.error('VNC: Security failure', e);
                            setConnectionStatus('auth_failed');
                        });
                        
                        // handle credentials request
                        rfbInstance.addEventListener('credentialsrequired', () => {
                            console.log('VNC: Credentials required, sending...');
                            rfbInstance.sendCredentials({ password: vncPassword });
                        });

                        setRfb(rfbInstance);
                        rfbRef.current = rfbInstance;
                        
                    } catch (e) {
                        console.error('VNC: Error:', e);
                        if(!cancelled) {
                            setConnectionStatus('load_error');
                        }
                    }
                };
                
                startVNC();
                
                return () => {
                    cancelled = true;
                    if(rfbRef.current) {
                        try {
                            rfbRef.current.disconnect();
                        } catch (e) {}
                        rfbRef.current = null;
                    }
                };
            }, [consoleInfo, clusterId, vm]);

            const handleFullscreen = () => {
                if(!document.fullscreenElement) {
                    containerRef.current?.requestFullscreen();
                    setIsFullscreen(true);
                } else {
                    document.exitFullscreen();
                    setIsFullscreen(false);
                }
            };

            const handleCtrlAltDel = () => {
                if(rfb) {
                    rfb.sendCtrlAltDel();
                }
            };

            const openInProxmox = () => {
                const url = `https://${consoleInfo.host}:8006/?console=${vm.type}&novnc=1&vmid=${vm.vmid}&node=${vm.node}`;
                window.open(url, '_blank');
            };

            return (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 modal-backdrop bg-black/80">
                    <div 
                        ref={containerRef}
                        className={`bg-proxmox-card border border-proxmox-border rounded-2xl shadow-2xl animate-scale-in overflow-hidden flex flex-col ${
                            isFullscreen ? 'w-full h-full rounded-none' : 'w-full max-w-5xl h-[80vh]'
                        }`}
                    >
                        {/* Header */}
                        <div className="flex items-center justify-between px-4 py-3 border-b border-proxmox-border bg-proxmox-dark">
                            <div className="flex items-center gap-3">
                                <Icons.Monitor />
                                <div>
                                    <h2 className="font-semibold text-white">{vm.name || `VM ${vm.vmid}`}</h2>
                                    <p className="text-xs text-gray-400">
                                        {vm.type.toUpperCase()} · {vm.node} · 
                                        <span className={`ml-1 ${
                                            connectionStatus === 'connected' ? 'text-green-400' :
                                            connectionStatus === 'connecting' ? 'text-yellow-400' :
                                            'text-red-400'
                                        }`}>
                                            {connectionStatus === 'connected' ? 'Connected' :
                                             connectionStatus === 'connecting' ? 'Connecting...' :
                                             'Error'}
                                        </span>
                                    </p>
                                </div>
                            </div>
                            <div className="flex items-center gap-2">
                                {vm.type === 'qemu' && connectionStatus === 'connected' && (
                                    <button
                                        onClick={handleCtrlAltDel}
                                        className="px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-xs text-gray-300 hover:text-white hover:border-proxmox-orange transition-colors"
                                    >
                                        Ctrl+Alt+Del
                                    </button>
                                )}
                                <button
                                    onClick={openInProxmox}
                                    className="px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded-lg text-xs text-gray-300 hover:text-white hover:border-proxmox-orange transition-colors"
                                >
                                    External
                                </button>
                                <button
                                    onClick={handleFullscreen}
                                    className="p-2 rounded-lg hover:bg-proxmox-hover transition-colors"
                                >
                                    {isFullscreen ? <Icons.Minimize /> : <Icons.Maximize />}
                                </button>
                                <button
                                    onClick={onClose}
                                    className="p-2 rounded-lg hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition-colors"
                                >
                                    <Icons.X />
                                </button>
                            </div>
                        </div>

                        {/* Console Area */}
                        <div className="flex-1 bg-black relative overflow-hidden">
                            {connectionStatus === 'connecting' && (
                                <div className="absolute inset-0 flex items-center justify-center bg-proxmox-darker">
                                    <div className="text-center">
                                        <div className="animate-spin w-8 h-8 border-2 border-proxmox-orange border-t-transparent rounded-full mx-auto mb-4"></div>
                                        <p className="text-gray-400">Connecting to console...</p>
                                    </div>
                                </div>
                            )}
                            {(connectionStatus === 'error' || connectionStatus === 'load_error' || connectionStatus === 'auth_failed') && (
                                <div className="absolute inset-0 flex items-center justify-center bg-proxmox-darker">
                                    <div className="text-center max-w-md p-6">
                                        <div className="text-red-400 text-xl mb-4">⚠️ {t('connectionError')}</div>
                                        
                                        {window.location.protocol === 'https:' && (
                                            <div className="text-gray-400 text-sm mb-4 p-4 bg-proxmox-dark rounded-lg text-left">
                                                <p className="mb-3 font-medium text-white">{t('certInstructions')}</p>
                                                <p className="mb-2">{t('certStep1')}</p>
                                                <a 
                                                    href={`https://${window.location.hostname}:${vncPort || ((parseInt(window.location.port) || 443) + 1)}/`}
                                                    target="_blank" 
                                                    rel="noopener noreferrer"
                                                    className="block text-proxmox-orange hover:underline mb-3 break-all"
                                                >
                                                    https://{window.location.hostname}:{vncPort || ((parseInt(window.location.port) || 443) + 1)}/
                                                </a>
                                                <p className="mb-2">{t('certStep2')}</p>
                                                <p className="text-xs text-gray-500">{t('certStep3')}</p>
                                            </div>
                                        )}
                                        
                                        <div className="flex gap-3 justify-center">
                                            <button
                                                onClick={() => {
                                                    const port = vncPort || ((parseInt(window.location.port) || 443) + 1);
                                                    window.open(`https://${window.location.hostname}:${port}/`, '_blank');
                                                }}
                                                className="px-4 py-2 bg-blue-600 rounded-lg text-white hover:bg-blue-700 transition-colors text-sm"
                                            >
                                                {t('acceptCert')}
                                            </button>
                                            <button
                                                onClick={openInProxmox}
                                                className="px-4 py-2 bg-proxmox-orange rounded-lg text-white hover:bg-orange-600 transition-colors text-sm"
                                            >
                                                {t('openInProxmox')}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            )}
                            <div ref={canvasRef} className="w-full h-full" />
                        </div>
                    </div>
                </div>
            );
        }

        // LW: Feb 2026 - Corporate Node Detail View (experimental)
        function CorporateNodeDetailView({ node, clusterId, clusterMetrics, clusterResources, onBack, onOpenNodeConfig, onMaintenanceToggle, onNodeAction, onStartUpdate, onSelectVm, addToast }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [activeDetailTab, setActiveDetailTab] = useState('summary');
            const [showActionsMenu, setShowActionsMenu] = useState(false);
            const [configSubTab, setConfigSubTab] = useState('network');
            const [monitorSubTab, setMonitorSubTab] = useState('performance');
            const [perfTimeframe, setPerfTimeframe] = useState('hour');
            const [loading, setLoading] = useState(false);
            const [data, setData] = useState({});
            // LW: Feb 2026 - edit states for configure tab
            const [editingDns, setEditingDns] = useState(false);
            const [editingHosts, setEditingHosts] = useState(false);
            const [dnsForm, setDnsForm] = useState({});
            const [hostsForm, setHostsForm] = useState('');
            const [showCertUpload, setShowCertUpload] = useState(false);
            const [certForm, setCertForm] = useState({ cert: '', key: '', restart: true });
            const [saving, setSaving] = useState(false);

            const metrics = clusterMetrics?.[node] || {};
            const nodeOnline = metrics.status !== 'offline';
            const isMaint = metrics.maintenance_mode;

            const authFetch = async (url, opts = {}) => {
                try { return await fetch(url, { ...opts, credentials: 'include', headers: { ...opts.headers, ...getAuthHeaders() } }); }
                catch(e) { console.error(e); return null; }
            };

            // LW: Feb 2026 - save handler for configure tab edits
            const handleSave = async (endpoint, payload, successMsg, method) => {
                setSaving(true);
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/${endpoint}`, {
                        method: method || 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    if (res && res.ok) {
                        addToast(successMsg, 'success');
                        // Reload relevant data
                        if (endpoint.includes('dns') || endpoint.includes('hosts') || endpoint.includes('time') || endpoint.includes('certificates') || endpoint.includes('syslog')) loadTabData('system');
                        else if (endpoint.includes('disk')) loadTabData('disks');
                        else if (endpoint.includes('repo')) loadTabData('repos');
                        else if (endpoint.includes('network')) loadTabData('network');
                    } else {
                        const err = res ? await res.json().catch(() => ({})) : {};
                        addToast(err.error || 'Error', 'error');
                    }
                } catch (e) { addToast('Error', 'error'); }
                setSaving(false);
            };

            const handleRepoToggle = async (repo) => {
                const payload = { enabled: !repo.Enabled };
                if (repo.is_other) { payload.file = repo.file; payload.index = repo.index; payload.name = repo.name; }
                await handleSave(`repos/${repo.id || repo.index}`, payload, repo.Enabled ? 'Repository disabled' : 'Repository enabled');
            };

            const handleCertUpload = async () => {
                setSaving(true);
                try {
                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/certificates/custom`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ certificates: certForm.cert, key: certForm.key, restart: certForm.restart, force: true })
                    });
                    if (res && res.ok) { addToast('Certificate uploaded', 'success'); setShowCertUpload(false); setCertForm({ cert: '', key: '', restart: true }); loadTabData('system'); }
                    else { const err = res ? await res.json().catch(() => ({})) : {}; addToast(err.error || 'Upload failed', 'error'); }
                } catch (e) { addToast('Upload failed', 'error'); }
                setSaving(false);
            };

            const formatBytes = b => {
                if(!b) return '0 B';
                const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
                const i = Math.floor(Math.log(b) / Math.log(k));
                return `${(b / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
            };

            const formatUptime = (s) => {
                if(!s) return '-';
                const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
                if(d > 0) return `${d}d ${h}h ${m}m`;
                if(h > 0) return `${h}h ${m}m`;
                return `${m}m`;
            };

            // Close actions menu on outside click
            useEffect(() => {
                if (!showActionsMenu) return;
                const close = () => setShowActionsMenu(false);
                document.addEventListener('click', close);
                return () => document.removeEventListener('click', close);
            }, [showActionsMenu]);

            // Fetch tab data
            const loadTabData = async (tab, tf) => {
                setLoading(true);
                try {
                    const endpoints = {
                        summary: [`${API_URL}/clusters/${clusterId}/nodes/${node}/summary`],
                        performance: [`${API_URL}/clusters/${clusterId}/nodes/${node}/rrddata?timeframe=${tf || perfTimeframe}`],
                        tasks: [`${API_URL}/clusters/${clusterId}/nodes/${node}/tasks?limit=50`],
                        network: [`${API_URL}/clusters/${clusterId}/nodes/${node}/network`],
                        system: [
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/dns`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/hosts`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/time`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/syslog?limit=100`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/certificates`,
                        ],
                        disks: [
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/disks`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/disks/lvm`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/disks/lvmthin`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/disks/zfs`,
                        ],
                        repos: [`${API_URL}/clusters/${clusterId}/nodes/${node}/repos`],
                        subscription: [`${API_URL}/clusters/${clusterId}/nodes/${node}/subscription`],
                        ceph: [
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/status`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/osd`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/mon`,
                            `${API_URL}/clusters/${clusterId}/nodes/${node}/ceph/pool`,
                        ],
                    };
                    const urls = endpoints[tab] || [];
                    if (urls.length === 0) { setLoading(false); return; }
                    const results = await Promise.all(urls.map(u => authFetch(u).then(r => r && r.ok ? r.json() : null).catch(() => null)));
                    // NS: Feb 2026 - Use functional setData to avoid stale closure bugs
                    setData(prev => {
                        const newData = { ...prev };
                        if (tab === 'summary') newData.summary = results[0];
                        else if (tab === 'performance') newData.performance = results[0];
                        else if (tab === 'tasks') newData.tasks = results[0];
                        else if (tab === 'network') newData.network = results[0];
                        else if (tab === 'system') {
                            newData.dns = results[0] || {};
                            newData.hosts = results[1]?.data || '';
                            newData.time = results[2] || {};
                            newData.syslog = results[3] || [];
                            newData.certificates = results[4] || [];
                        }
                        else if (tab === 'disks') {
                            newData.disks = results[0] || [];
                            newData.lvm = results[1] || [];
                            newData.lvmthin = results[2] || [];
                            newData.zfs = results[3] || [];
                        }
                        else if (tab === 'repos') newData.repos = results[0]?.repositories || [];
                        else if (tab === 'subscription') newData.subscription = results[0] || {};
                        else if (tab === 'ceph') {
                            newData.ceph = { status: results[0], osd: results[1] || [], mon: results[2] || [], pools: results[3] || [], available: results[0] !== null };
                        }
                        return newData;
                    });
                } catch (e) { console.error(e); }
                setLoading(false);
            };

            // LW: Feb 2026 - reset data and load summary when node changes
            useEffect(() => { setData({}); setConfigSubTab('network'); setMonitorSubTab('performance'); setActiveDetailTab('summary'); loadTabData('summary'); }, [node]);

            // Load data when tab changes
            useEffect(() => {
                if (activeDetailTab === 'summary' && !data.summary) loadTabData('summary');
                else if (activeDetailTab === 'monitor') {
                    if (monitorSubTab === 'performance' && !data.performance) loadTabData('performance');
                    else if (monitorSubTab === 'tasks' && !data.tasks) loadTabData('tasks');
                }
                else if (activeDetailTab === 'configure') {
                    if (configSubTab === 'network' && !data.network) loadTabData('network');
                    else if (['dns', 'hosts', 'time', 'certs', 'syslog'].includes(configSubTab) && !data.dns) loadTabData('system');
                    else if (['disks', 'lvm', 'lvmthin', 'zfs'].includes(configSubTab) && !data.disks) loadTabData('disks');
                    else if (configSubTab === 'repos' && !data.repos) loadTabData('repos');
                    else if (configSubTab === 'ceph' && !data.ceph) loadTabData('ceph');
                }
                else if (activeDetailTab === 'subscription' && !data.subscription) loadTabData('subscription');
            }, [activeDetailTab, configSubTab, monitorSubTab]);

            const handlePerfTimeframeChange = (tf) => {
                setPerfTimeframe(tf);
                loadTabData('performance', tf);
            };

            const nodeVms = (clusterResources || []).filter(r => r.node === node && (r.type === 'qemu' || r.type === 'lxc'));
            const runningVms = nodeVms.filter(v => v.status === 'running').length;

            // LW: Feb 2026 - backend sends flat fields: cpu_percent, mem_used, mem_total, disk_used, disk_total
            // Swap only available from summary API, not clusterMetrics
            const cpuPercent = metrics.cpu_percent?.toFixed(1) || '0.0';
            const ramUsed = metrics.mem_used || 0;
            const ramTotal = metrics.mem_total || 0;
            const ramPercent = ramTotal > 0 ? ((ramUsed / ramTotal) * 100).toFixed(1) : '0.0';
            const swapUsed = data.summary?.swap?.used || 0;
            const swapTotal = data.summary?.swap?.total || 0;
            const swapPercent = swapTotal > 0 ? ((swapUsed / swapTotal) * 100).toFixed(1) : '0.0';
            const rootUsed = metrics.disk_used || 0;
            const rootTotal = metrics.disk_total || 0;
            const rootPercent = rootTotal > 0 ? ((rootUsed / rootTotal) * 100).toFixed(1) : '0.0';

            return (
                <div className="space-y-0">
                    {/* Header Bar */}
                    <div className="flex items-center justify-between px-4 py-2 border-b border-proxmox-border" style={{background: '#22343c'}}>
                        <div className="flex items-center gap-2">
                            <button onClick={onBack} className="p-1 hover:text-white" style={{color: '#adbbc4'}} title={t('backToList')}>
                                <Icons.ChevronLeft className="w-4 h-4" />
                            </button>
                            <Icons.Server className="w-4 h-4" style={{color: nodeOnline ? '#49afd9' : '#f54f47'}} />
                            <span className="text-[14px] font-medium" style={{color: '#e9ecef'}}>{node}</span>
                            <span className={`corp-badge ${nodeOnline ? (isMaint ? 'corp-badge-maintenance' : 'corp-badge-online') : 'corp-badge-offline'}`}>
                                {isMaint ? t('maintenance') : nodeOnline ? t('online') : t('offline')}
                            </span>
                        </div>
                        <div className="corp-toolbar flex items-center gap-1">
                            <div className="relative">
                                <button onClick={(e) => { e.stopPropagation(); setShowActionsMenu(!showActionsMenu); }}>
                                    {t('actions')} <Icons.ChevronDown className="w-3 h-3" />
                                </button>
                                {showActionsMenu && (
                                    <div className="corp-dropdown absolute right-0 top-full mt-1 w-52 z-50 py-1" onClick={(e) => e.stopPropagation()}>
                                        <button onClick={() => { onMaintenanceToggle(node, !isMaint); setShowActionsMenu(false); }} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#adbbc4'}}>
                                            <Icons.Wrench className="w-3.5 h-3.5" /> {isMaint ? t('disableMaintenance') || 'Disable Maintenance' : t('maintenance')}
                                        </button>
                                        <button onClick={() => { onNodeAction(node, 'reboot'); setShowActionsMenu(false); }} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#adbbc4'}}>
                                            <Icons.RefreshCw className="w-3.5 h-3.5" /> {t('rebootNode')}
                                        </button>
                                        <button onClick={() => { onNodeAction(node, 'shutdown'); setShowActionsMenu(false); }} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#f54f47'}}>
                                            <Icons.Power className="w-3.5 h-3.5" /> {t('shutdownNode')}
                                        </button>
                                        <button onClick={() => { onStartUpdate(node); setShowActionsMenu(false); }} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#adbbc4'}}>
                                            <Icons.Download className="w-3.5 h-3.5" /> {t('update') || 'Update'}
                                        </button>
                                        <div className="my-1" style={{borderTop: '1px solid #485764'}}></div>
                                        <button onClick={() => { onOpenNodeConfig(node); setShowActionsMenu(false); }} className="w-full text-left px-3 py-1.5 text-[13px] flex items-center gap-2" style={{color: '#adbbc4'}}>
                                            <Icons.Settings className="w-3.5 h-3.5" /> {t('nodeSettings')}
                                        </button>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Tab Strip */}
                    <div className="corp-tab-strip px-4" style={{background: '#22343c'}}>
                        {['summary', 'monitor', 'configure', 'vms', 'shell', 'subscription'].map(tab => (
                            <button key={tab} className={activeDetailTab === tab ? 'active' : ''} onClick={() => setActiveDetailTab(tab)}>
                                {tab === 'summary' ? t('summary') : tab === 'monitor' ? t('monitor') : tab === 'configure' ? t('configure') : tab === 'vms' ? 'VMs' : tab === 'shell' ? 'Shell' : t('subscriptionInfo')}
                            </button>
                        ))}
                    </div>

                    {/* Tab Content */}
                    <div className="p-4">
                        {loading && !data.summary && (
                            <div className="flex items-center justify-center h-32">
                                <Icons.RotateCw className="w-5 h-5 animate-spin" style={{color: '#49afd9'}} />
                            </div>
                        )}

                        {/* Summary Tab */}
                        {activeDetailTab === 'summary' && (
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                {/* Host Details card */}
                                <div style={{border: '1px solid #485764'}}>
                                    <div className="px-3 py-2" style={{background: '#22343c', borderBottom: '1px solid #485764'}}>
                                        <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('hostDetails')}</span>
                                    </div>
                                    <table className="corp-property-grid">
                                        <tbody>
                                            <tr><td>{t('status')}</td><td className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full" style={{background: nodeOnline ? '#60b515' : '#f54f47'}}></span> {isMaint ? t('maintenance') : nodeOnline ? t('online') : t('offline')}</td></tr>
                                            <tr><td>{t('pveVersion')}</td><td>{data.summary?.pveversion || metrics.pveversion || '-'}</td></tr>
                                            <tr><td>{t('kernelVersion')}</td><td style={{fontFamily: 'monospace', fontSize: '12px'}}>{data.summary?.kversion || '-'}</td></tr>
                                            <tr><td>{t('cpuModel')}</td><td>{data.summary?.cpuinfo?.model || '-'}</td></tr>
                                            <tr><td>{t('cores')}</td><td>{data.summary?.cpuinfo?.cores || '-'} ({data.summary?.cpuinfo?.cpus || '-'} {t('logicalProcessors')})</td></tr>
                                            <tr><td>{t('cpuSockets')}</td><td>{data.summary?.cpuinfo?.sockets || '-'}</td></tr>
                                            <tr><td>VMs</td><td>{nodeVms.length} ({runningVms} {t('running').toLowerCase()})</td></tr>
                                            <tr><td>{t('uptime')}</td><td>{formatUptime(data.summary?.uptime || metrics.uptime)}</td></tr>
                                        </tbody>
                                    </table>
                                </div>

                                {/* Capacity & Usage card */}
                                <div style={{border: '1px solid #485764'}}>
                                    <div className="px-3 py-2" style={{background: '#22343c', borderBottom: '1px solid #485764'}}>
                                        <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('capacityUsage')}</span>
                                    </div>
                                    <div className="p-3 space-y-3">
                                        {[
                                            { label: 'CPU', percent: cpuPercent, used: `${cpuPercent}%`, total: `${data.summary?.cpuinfo?.cpus || '-'} ${t('logicalProcessors')}`, color: '#49afd9' },
                                            { label: 'RAM', percent: ramPercent, used: formatBytes(ramUsed), total: formatBytes(ramTotal), color: '#9b59b6' },
                                            { label: 'Swap', percent: swapPercent, used: formatBytes(swapUsed), total: formatBytes(swapTotal), color: '#ec4899' },
                                            { label: 'Root FS', percent: rootPercent, used: formatBytes(rootUsed), total: formatBytes(rootTotal), color: '#60b515' },
                                        ].map(item => (
                                            <div key={item.label}>
                                                <div className="flex items-center justify-between mb-1">
                                                    <span className="text-[12px]" style={{color: '#adbbc4'}}>{item.label}</span>
                                                    <span className="text-[12px]" style={{color: '#e9ecef'}}>{item.used} / {item.total}</span>
                                                </div>
                                                <div className="corp-capacity-bar">
                                                    <div style={{width: `${Math.min(item.percent, 100)}%`, background: item.color}}></div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* Hardware card */}
                                <div style={{border: '1px solid #485764'}}>
                                    <div className="px-3 py-2" style={{background: '#22343c', borderBottom: '1px solid #485764'}}>
                                        <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('hardwareInfo')}</span>
                                    </div>
                                    <table className="corp-property-grid">
                                        <tbody>
                                            <tr><td>CPU</td><td>{data.summary?.cpuinfo?.model || '-'}</td></tr>
                                            <tr><td>{t('totalRam')}</td><td>{formatBytes(ramTotal)}</td></tr>
                                            <tr><td>{t('networkInterfaces')}</td><td>{data.network ? (Array.isArray(data.network) ? data.network.length : '-') : '-'}</td></tr>
                                            <tr><td>{t('rootFilesystem')}</td><td>{formatBytes(rootTotal)}</td></tr>
                                        </tbody>
                                    </table>
                                </div>

                                {/* Related Objects card */}
                                <div style={{border: '1px solid #485764'}}>
                                    <div className="px-3 py-2" style={{background: '#22343c', borderBottom: '1px solid #485764'}}>
                                        <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('relatedObjects')}</span>
                                    </div>
                                    <table className="corp-property-grid">
                                        <tbody>
                                            <tr><td>QEMU VMs</td><td>{nodeVms.filter(v => v.type === 'qemu').length}</td></tr>
                                            <tr><td>LXC CTs</td><td>{nodeVms.filter(v => v.type === 'lxc').length}</td></tr>
                                            <tr><td>{t('running')}</td><td>{runningVms}</td></tr>
                                            <tr><td>{t('stopped')}</td><td>{nodeVms.length - runningVms}</td></tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}

                        {/* Monitor Tab */}
                        {activeDetailTab === 'monitor' && (
                            <div className="flex gap-0" style={{minHeight: '400px'}}>
                                <div className="corp-subnav">
                                    <button className={`corp-subnav-item ${monitorSubTab === 'performance' ? 'active' : ''}`} onClick={() => setMonitorSubTab('performance')}>{t('performance')}</button>
                                    <button className={`corp-subnav-item ${monitorSubTab === 'tasks' ? 'active' : ''}`} onClick={() => { setMonitorSubTab('tasks'); if (!data.tasks) loadTabData('tasks'); }}>{t('tasks')}</button>
                                </div>
                                <div className="flex-1 pl-4">
                                    {monitorSubTab === 'performance' && (
                                        <div className="space-y-4">
                                            <div className="flex items-center justify-between">
                                                <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('performance')}</span>
                                                <div className="flex gap-1">
                                                    {['hour', 'day', 'week', 'month', 'year'].map(tf => (
                                                        <button key={tf} onClick={() => handlePerfTimeframeChange(tf)}
                                                            className="px-2 py-1 text-[11px]"
                                                            style={perfTimeframe === tf ? {background: '#324f61', color: '#e9ecef', border: '1px solid #49afd9'} : {color: '#adbbc4', border: '1px solid #485764'}}
                                                        >{tf.charAt(0).toUpperCase() + tf.slice(1)}</button>
                                                    ))}
                                                </div>
                                            </div>
                                            {loading && !data.performance ? (
                                                <div className="flex items-center justify-center h-32"><Icons.RotateCw className="w-5 h-5 animate-spin" style={{color: '#49afd9'}} /></div>
                                            ) : data.performance?.metrics ? (
                                                <div className="space-y-3">
                                                    <div className="grid grid-cols-2 gap-3">
                                                        <LineChart data={data.performance.metrics.cpu} timestamps={data.performance.timestamps} label="CPU" color="#49afd9" unit="%" yMin={0} yMax={100} />
                                                        <LineChart data={data.performance.metrics.memory} timestamps={data.performance.timestamps} label="Memory" color="#9b59b6" unit="%" yMin={0} yMax={100} />
                                                        <LineChart data={data.performance.metrics.iowait} timestamps={data.performance.timestamps} label="IO Wait" color="#eab308" unit="%" />
                                                        <LineChart data={data.performance.metrics.loadavg} timestamps={data.performance.timestamps} label="Load Average" color="#22c55e" unit="" />
                                                    </div>
                                                    <LineChart datasets={[{label: 'Net In', data: data.performance.metrics.net_in, color: '#06b6d4'}, {label: 'Net Out', data: data.performance.metrics.net_out, color: '#8b5cf6'}]} timestamps={data.performance.timestamps} label="Network I/O" unit=" KB/s" />
                                                    <div className="grid grid-cols-2 gap-3">
                                                        <LineChart data={data.performance.metrics.swap} timestamps={data.performance.timestamps} label="Swap" color="#ec4899" unit="%" yMin={0} yMax={100} />
                                                        <LineChart data={data.performance.metrics.rootfs} timestamps={data.performance.timestamps} label="Root FS" color="#a855f7" unit="%" yMin={0} yMax={100} />
                                                    </div>
                                                </div>
                                            ) : (
                                                <div className="text-center py-8" style={{color: '#728b9a'}}><Icons.BarChart className="w-8 h-8 mx-auto mb-2 opacity-50" /><p className="text-[13px]">No performance data available</p></div>
                                            )}
                                        </div>
                                    )}
                                    {monitorSubTab === 'tasks' && (
                                        <div>
                                            <span className="text-[13px] font-medium mb-3 block" style={{color: '#e9ecef'}}>{t('tasks')}</span>
                                            {loading && !data.tasks ? (
                                                <div className="flex items-center justify-center h-32"><Icons.RotateCw className="w-5 h-5 animate-spin" style={{color: '#49afd9'}} /></div>
                                            ) : (
                                                <table className="corp-datagrid">
                                                    <thead><tr><th>{t('type')}</th><th>{t('status')}</th><th>UPID</th><th>{t('started') || 'Started'}</th></tr></thead>
                                                    <tbody>
                                                        {(data.tasks || []).slice(0, 50).map((task, i) => (
                                                            <tr key={i}>
                                                                <td>{task.type || '-'}</td>
                                                                <td><span className={`corp-badge ${task.status === 'OK' || task.status === 'running' ? 'corp-badge-running' : task.status ? 'corp-badge-offline' : 'corp-badge-stopped'}`}>{task.status || '-'}</span></td>
                                                                <td className="text-[11px] font-mono" style={{color: '#728b9a'}}>{task.upid ? task.upid.substring(0, 30) + '...' : '-'}</td>
                                                                <td>{task.starttime ? new Date(task.starttime * 1000).toLocaleString() : '-'}</td>
                                                            </tr>
                                                        ))}
                                                        {(!data.tasks || data.tasks.length === 0) && <tr><td colSpan={4} className="text-center py-4" style={{color: '#728b9a'}}>No tasks</td></tr>}
                                                    </tbody>
                                                </table>
                                            )}
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Configure Tab */}
                        {activeDetailTab === 'configure' && (
                            <div className="flex gap-0" style={{minHeight: '400px'}}>
                                <div className="corp-subnav">
                                    <div className="corp-subnav-header">{t('network')}</div>
                                    <button className={`corp-subnav-item ${configSubTab === 'network' ? 'active' : ''}`} onClick={() => setConfigSubTab('network')}>{t('network')}</button>
                                    <div className="corp-subnav-header">{t('systemInfo')}</div>
                                    <button className={`corp-subnav-item ${configSubTab === 'dns' ? 'active' : ''}`} onClick={() => { setConfigSubTab('dns'); if (!data.dns) loadTabData('system'); }}>{t('dns')}</button>
                                    <button className={`corp-subnav-item ${configSubTab === 'hosts' ? 'active' : ''}`} onClick={() => { setConfigSubTab('hosts'); if (!data.dns) loadTabData('system'); }}>{t('hostsFile')}</button>
                                    <button className={`corp-subnav-item ${configSubTab === 'time' ? 'active' : ''}`} onClick={() => { setConfigSubTab('time'); if (!data.dns) loadTabData('system'); }}>{t('timeConfig')}</button>
                                    <button className={`corp-subnav-item ${configSubTab === 'certs' ? 'active' : ''}`} onClick={() => { setConfigSubTab('certs'); if (!data.dns) loadTabData('system'); }}>{t('certificates')}</button>
                                    <button className={`corp-subnav-item ${configSubTab === 'syslog' ? 'active' : ''}`} onClick={() => { setConfigSubTab('syslog'); if (!data.dns) loadTabData('system'); }}>{t('syslog')}</button>
                                    <div className="corp-subnav-header">{t('storage')}</div>
                                    <button className={`corp-subnav-item ${configSubTab === 'disks' ? 'active' : ''}`} onClick={() => { setConfigSubTab('disks'); if (!data.disks) loadTabData('disks'); }}>{t('disks')}</button>
                                    <button className={`corp-subnav-item ${configSubTab === 'lvm' ? 'active' : ''}`} onClick={() => { setConfigSubTab('lvm'); if (!data.disks) loadTabData('disks'); }}>{t('lvmStorage')}</button>
                                    <button className={`corp-subnav-item ${configSubTab === 'lvmthin' ? 'active' : ''}`} onClick={() => { setConfigSubTab('lvmthin'); if (!data.disks) loadTabData('disks'); }}>{t('lvmThinStorage')}</button>
                                    <button className={`corp-subnav-item ${configSubTab === 'zfs' ? 'active' : ''}`} onClick={() => { setConfigSubTab('zfs'); if (!data.disks) loadTabData('disks'); }}>{t('zfsStorage')}</button>
                                    <div className="corp-subnav-header">Extras</div>
                                    <button className={`corp-subnav-item ${configSubTab === 'repos' ? 'active' : ''}`} onClick={() => { setConfigSubTab('repos'); if (!data.repos) loadTabData('repos'); }}>{t('repositories')}</button>
                                    <button className={`corp-subnav-item ${configSubTab === 'ceph' ? 'active' : ''}`} onClick={() => { setConfigSubTab('ceph'); if (!data.ceph) loadTabData('ceph'); }}>Ceph</button>
                                </div>
                                <div className="flex-1 pl-4">
                                    {loading && !data.network && !data.dns && !data.disks ? (
                                        <div className="flex items-center justify-center h-32"><Icons.RotateCw className="w-5 h-5 animate-spin" style={{color: '#49afd9'}} /></div>
                                    ) : (
                                        <>
                                            {/* LW: Feb 2026 - full network editing like modern NodeModal */}
                                            {configSubTab === 'network' && (
                                                <div>
                                                    <div className="flex items-center justify-between mb-3">
                                                        <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('network')}</span>
                                                        <div className="flex gap-1">
                                                            <div className="relative">
                                                                <button onClick={() => setData(prev => ({...prev, showCreateMenu: !prev.showCreateMenu}))}
                                                                    className="px-2 py-1 text-[11px] flex items-center gap-1" style={{color: '#49afd9', border: '1px solid #485764'}}>
                                                                    <Icons.Plus className="w-3 h-3" /> Create
                                                                </button>
                                                                {data.showCreateMenu && (
                                                                    <div className="absolute top-full right-0 mt-1 z-10 min-w-[160px]" style={{background: '#22343c', border: '1px solid #485764'}}>
                                                                        {['bridge', 'bond', 'vlan', 'OVSBridge', 'OVSBond', 'OVSIntPort'].map(ifType => (
                                                                            <button key={ifType} onClick={() => setData(prev => ({...prev, showCreateMenu: false, editIface: { type: ifType, iface: '', isNew: true }}))}
                                                                                className="w-full px-3 py-1.5 text-left text-[12px] hover:bg-[#324f61]" style={{color: '#adbbc4'}}>
                                                                                Linux {ifType.charAt(0).toUpperCase() + ifType.slice(1)}
                                                                            </button>
                                                                        ))}
                                                                    </div>
                                                                )}
                                                            </div>
                                                            <button onClick={async () => { const res = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/network`, { method: 'PUT' }); addToast(res && res.ok ? 'Network config applied' : 'Error', res && res.ok ? 'success' : 'error'); loadTabData('network'); }}
                                                                className="px-2 py-1 text-[11px]" style={{color: '#60b515', border: '1px solid rgba(96,181,21,0.3)'}}>Apply</button>
                                                            <button onClick={async () => { const res = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/network`, { method: 'DELETE' }); addToast(res && res.ok ? 'Changes reverted' : 'Error', res && res.ok ? 'success' : 'error'); loadTabData('network'); }}
                                                                className="px-2 py-1 text-[11px]" style={{color: '#efc006', border: '1px solid rgba(239,192,6,0.3)'}}>Revert</button>
                                                        </div>
                                                    </div>
                                                    <table className="corp-datagrid">
                                                        <thead><tr><th>{t('name')}</th><th>{t('type')}</th><th>CIDR</th><th>Gateway</th><th>{t('active') || 'Active'}</th><th style={{width: '60px'}}></th></tr></thead>
                                                        <tbody>
                                                            {(Array.isArray(data.network) ? data.network : []).map((iface, i) => (
                                                                <tr key={i}>
                                                                    <td style={{fontFamily: 'monospace', fontSize: '12px'}}>{iface.iface || iface.name || '-'}</td>
                                                                    <td>{iface.type || '-'}</td>
                                                                    <td style={{fontFamily: 'monospace', fontSize: '12px'}}>{iface.cidr || iface.address || '-'}</td>
                                                                    <td style={{fontFamily: 'monospace', fontSize: '12px'}}>{iface.gateway || '-'}</td>
                                                                    <td><span className="w-2 h-2 rounded-full inline-block" style={{background: iface.active ? '#60b515' : '#728b9a'}}></span></td>
                                                                    <td>
                                                                        <div className="flex gap-1">
                                                                            <button onClick={() => setData(prev => ({...prev, editIface: {...iface, isNew: false}}))}
                                                                                className="p-1 hover:bg-[#324f61]" title="Edit" style={{color: '#49afd9'}}>
                                                                                <Icons.Cog className="w-3 h-3" />
                                                                            </button>
                                                                            <button onClick={async () => {
                                                                                    if (!confirm(`${t('delete')} ${iface.iface}?`)) return;
                                                                                    const res = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/network/${iface.iface}`, { method: 'DELETE' });
                                                                                    addToast(res && res.ok ? `${iface.iface} ${t('deleted')}` : 'Error', res && res.ok ? 'success' : 'error'); loadTabData('network');
                                                                                }}
                                                                                className="p-1 hover:bg-[#324f61]" title="Delete" style={{color: '#e57373'}}>
                                                                                <Icons.Trash className="w-3 h-3" />
                                                                            </button>
                                                                        </div>
                                                                    </td>
                                                                </tr>
                                                            ))}
                                                            {(!data.network || data.network.length === 0) && <tr><td colSpan={6} className="text-center py-4" style={{color: '#728b9a'}}>No network interfaces</td></tr>}
                                                        </tbody>
                                                    </table>
                                                    {/* LW: Feb 2026 - edit/create interface modal */}
                                                    {data.editIface && (
                                                        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" style={{background: 'rgba(0,0,0,0.7)'}}>
                                                            <div className="w-full max-w-xl" style={{background: '#1b2a32', border: '1px solid #485764'}}>
                                                                <div className="px-4 py-3 flex items-center justify-between" style={{borderBottom: '1px solid #485764', background: '#22343c'}}>
                                                                    <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>
                                                                        {data.editIface.isNew ? `Create: Linux ${data.editIface.type}` : `Edit: ${data.editIface.iface}`}
                                                                    </span>
                                                                    <button onClick={() => setData(prev => ({...prev, editIface: null}))} style={{color: '#728b9a'}}><Icons.X className="w-4 h-4" /></button>
                                                                </div>
                                                                <div className="p-4 space-y-3">
                                                                    <div className="grid grid-cols-2 gap-3">
                                                                        <div>
                                                                            <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>{t('name')}</label>
                                                                            <input type="text" value={data.editIface.iface || ''} disabled={!data.editIface.isNew}
                                                                                onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, iface: e.target.value}}))}
                                                                                placeholder={data.editIface.type === 'bridge' ? 'vmbr0' : data.editIface.type === 'bond' ? 'bond0' : 'vlan0'}
                                                                                className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white disabled:opacity-50" />
                                                                        </div>
                                                                        <div>
                                                                            <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>IPv4/CIDR</label>
                                                                            <input type="text" value={data.editIface.cidr || ''}
                                                                                onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, cidr: e.target.value}}))}
                                                                                placeholder="192.168.1.1/24"
                                                                                className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white font-mono" />
                                                                        </div>
                                                                        <div>
                                                                            <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>Gateway (IPv4)</label>
                                                                            <input type="text" value={data.editIface.gateway || ''}
                                                                                onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, gateway: e.target.value}}))}
                                                                                placeholder="192.168.1.1"
                                                                                className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white font-mono" />
                                                                        </div>
                                                                        <div>
                                                                            <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>IPv6/CIDR</label>
                                                                            <input type="text" value={data.editIface.cidr6 || ''}
                                                                                onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, cidr6: e.target.value}}))}
                                                                                className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white font-mono" />
                                                                        </div>
                                                                        <div>
                                                                            <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>Gateway (IPv6)</label>
                                                                            <input type="text" value={data.editIface.gateway6 || ''}
                                                                                onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, gateway6: e.target.value}}))}
                                                                                className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white font-mono" />
                                                                        </div>
                                                                        <div>
                                                                            <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>MTU</label>
                                                                            <input type="number" value={data.editIface.mtu || ''}
                                                                                onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, mtu: e.target.value}}))}
                                                                                placeholder="1500"
                                                                                className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white" />
                                                                        </div>
                                                                    </div>
                                                                    {data.editIface.type === 'bridge' && (
                                                                        <div className="grid grid-cols-2 gap-3">
                                                                            <div>
                                                                                <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>Bridge Ports</label>
                                                                                <input type="text" value={data.editIface.bridge_ports || ''}
                                                                                    onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, bridge_ports: e.target.value}}))}
                                                                                    placeholder="ens18"
                                                                                    className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white" />
                                                                            </div>
                                                                            <div className="flex items-center pt-4">
                                                                                <label className="flex items-center gap-2 text-[12px]" style={{color: '#adbbc4'}}>
                                                                                    <input type="checkbox" checked={data.editIface.bridge_vlan_aware || false}
                                                                                        onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, bridge_vlan_aware: e.target.checked}}))} />
                                                                                    VLAN aware
                                                                                </label>
                                                                            </div>
                                                                        </div>
                                                                    )}
                                                                    {data.editIface.type === 'bond' && (
                                                                        <div className="grid grid-cols-2 gap-3">
                                                                            <div>
                                                                                <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>Slaves</label>
                                                                                <input type="text" value={data.editIface.slaves || ''}
                                                                                    onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, slaves: e.target.value}}))}
                                                                                    placeholder="ens18 ens19"
                                                                                    className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white" />
                                                                            </div>
                                                                            <div>
                                                                                <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>Mode</label>
                                                                                <select value={data.editIface.bond_mode || 'balance-rr'}
                                                                                    onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, bond_mode: e.target.value}}))}
                                                                                    className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white">
                                                                                    <option value="balance-rr">balance-rr</option>
                                                                                    <option value="active-backup">active-backup</option>
                                                                                    <option value="balance-xor">balance-xor</option>
                                                                                    <option value="broadcast">broadcast</option>
                                                                                    <option value="802.3ad">LACP (802.3ad)</option>
                                                                                    <option value="balance-tlb">balance-tlb</option>
                                                                                    <option value="balance-alb">balance-alb</option>
                                                                                </select>
                                                                            </div>
                                                                            <div>
                                                                                <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>Hash Policy</label>
                                                                                <select value={data.editIface.bond_xmit_hash_policy || ''}
                                                                                    onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, bond_xmit_hash_policy: e.target.value}}))}
                                                                                    className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white">
                                                                                    <option value="">Default</option>
                                                                                    <option value="layer2">layer2</option>
                                                                                    <option value="layer2+3">layer2+3</option>
                                                                                    <option value="layer3+4">layer3+4</option>
                                                                                </select>
                                                                            </div>
                                                                            <div>
                                                                                <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>Bond Primary</label>
                                                                                <input type="text" value={data.editIface['bond-primary'] || ''}
                                                                                    onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, 'bond-primary': e.target.value}}))}
                                                                                    className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white" />
                                                                            </div>
                                                                        </div>
                                                                    )}
                                                                    {data.editIface.type === 'vlan' && (
                                                                        <div className="grid grid-cols-2 gap-3">
                                                                            <div>
                                                                                <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>VLAN raw device</label>
                                                                                <input type="text" value={data.editIface['vlan-raw-device'] || ''}
                                                                                    onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, 'vlan-raw-device': e.target.value}}))}
                                                                                    placeholder="vmbr0"
                                                                                    className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white" />
                                                                            </div>
                                                                            <div>
                                                                                <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>VLAN Tag</label>
                                                                                <input type="number" value={data.editIface['vlan-id'] || ''}
                                                                                    onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, 'vlan-id': e.target.value}}))}
                                                                                    placeholder="100"
                                                                                    className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white" />
                                                                            </div>
                                                                        </div>
                                                                    )}
                                                                    <div className="grid grid-cols-2 gap-3">
                                                                        <div className="flex items-center gap-2">
                                                                            <label className="flex items-center gap-2 text-[12px]" style={{color: '#adbbc4'}}>
                                                                                <input type="checkbox" checked={data.editIface.autostart !== 0}
                                                                                    onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, autostart: e.target.checked ? 1 : 0}}))} />
                                                                                Autostart
                                                                            </label>
                                                                        </div>
                                                                        <div>
                                                                            <label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>Comment</label>
                                                                            <input type="text" value={data.editIface.comments || ''}
                                                                                onChange={e => setData(prev => ({...prev, editIface: {...prev.editIface, comments: e.target.value}}))}
                                                                                className="w-full px-2 py-1.5 text-[12px] bg-proxmox-dark border border-proxmox-border text-white" />
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                                <div className="px-4 py-3 flex justify-end gap-2" style={{borderTop: '1px solid #485764'}}>
                                                                    <button onClick={() => setData(prev => ({...prev, editIface: null}))}
                                                                        className="px-3 py-1.5 text-[12px]" style={{color: '#adbbc4', border: '1px solid #485764'}}>{t('cancel')}</button>
                                                                    <button onClick={async () => {
                                                                        const iface = data.editIface;
                                                                        if (!iface.iface) { addToast(t('nameRequired') || 'Name required', 'error'); return; }
                                                                        const payload = { ...iface };
                                                                        delete payload.isNew; delete payload.active; delete payload.exists; delete payload.families; delete payload.method; delete payload.method6; delete payload.priority;
                                                                        const url = iface.isNew ? `${API_URL}/clusters/${clusterId}/nodes/${node}/network` : `${API_URL}/clusters/${clusterId}/nodes/${node}/network/${iface.iface}`;
                                                                        const method = iface.isNew ? 'POST' : 'PUT';
                                                                        const res = await authFetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                                                                        if (res && res.ok) {
                                                                            addToast(iface.isNew ? (t('interfaceCreated') || 'Interface created') : (t('interfaceUpdated') || 'Interface updated'), 'success');
                                                                            setData(prev => ({...prev, editIface: null}));
                                                                            loadTabData('network');
                                                                        } else { addToast('Error', 'error'); }
                                                                    }} className="px-3 py-1.5 text-[12px]" style={{color: '#fff', background: '#49afd9', border: 'none'}}>
                                                                        {data.editIface.isNew ? 'Create' : t('save')}
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                            {configSubTab === 'dns' && (
                                                <div>
                                                    <div className="flex items-center justify-between mb-3">
                                                        <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('dns')}</span>
                                                        {!editingDns ? (
                                                            <button onClick={() => { setEditingDns(true); setDnsForm({ search: data.dns?.search || '', dns1: data.dns?.dns1 || '', dns2: data.dns?.dns2 || '', dns3: data.dns?.dns3 || '' }); }}
                                                                className="px-2 py-1 text-[11px]" style={{color: '#49afd9', border: '1px solid #485764'}}>{t('edit')}</button>
                                                        ) : (
                                                            <div className="flex gap-1">
                                                                <button onClick={() => setEditingDns(false)} className="px-2 py-1 text-[11px]" style={{color: '#adbbc4', border: '1px solid #485764'}}>{t('cancel')}</button>
                                                                <button onClick={() => { handleSave('dns', dnsForm, 'DNS saved'); setEditingDns(false); }} disabled={saving}
                                                                    className="px-2 py-1 text-[11px]" style={{color: '#60b515', border: '1px solid rgba(96,181,21,0.3)'}}>{saving ? '...' : t('save')}</button>
                                                            </div>
                                                        )}
                                                    </div>
                                                    {editingDns ? (
                                                        <div className="space-y-2">
                                                            <div><label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>Search Domain</label><input value={dnsForm.search} onChange={e => setDnsForm({...dnsForm, search: e.target.value})} className="w-full px-2 py-1.5 text-[13px] bg-proxmox-dark border border-proxmox-border text-white" /></div>
                                                            <div><label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>DNS 1</label><input value={dnsForm.dns1} onChange={e => setDnsForm({...dnsForm, dns1: e.target.value})} className="w-full px-2 py-1.5 text-[13px] bg-proxmox-dark border border-proxmox-border text-white font-mono" /></div>
                                                            <div><label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>DNS 2</label><input value={dnsForm.dns2} onChange={e => setDnsForm({...dnsForm, dns2: e.target.value})} className="w-full px-2 py-1.5 text-[13px] bg-proxmox-dark border border-proxmox-border text-white font-mono" /></div>
                                                            <div><label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>DNS 3</label><input value={dnsForm.dns3} onChange={e => setDnsForm({...dnsForm, dns3: e.target.value})} className="w-full px-2 py-1.5 text-[13px] bg-proxmox-dark border border-proxmox-border text-white font-mono" /></div>
                                                        </div>
                                                    ) : (
                                                        <table className="corp-property-grid">
                                                            <tbody>
                                                                <tr><td>Search Domain</td><td>{data.dns?.search || '-'}</td></tr>
                                                                <tr><td>DNS 1</td><td style={{fontFamily: 'monospace', fontSize: '12px'}}>{data.dns?.dns1 || '-'}</td></tr>
                                                                <tr><td>DNS 2</td><td style={{fontFamily: 'monospace', fontSize: '12px'}}>{data.dns?.dns2 || '-'}</td></tr>
                                                                <tr><td>DNS 3</td><td style={{fontFamily: 'monospace', fontSize: '12px'}}>{data.dns?.dns3 || '-'}</td></tr>
                                                            </tbody>
                                                        </table>
                                                    )}
                                                </div>
                                            )}
                                            {configSubTab === 'hosts' && (
                                                <div>
                                                    <div className="flex items-center justify-between mb-3">
                                                        <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('hostsFile')}</span>
                                                        {!editingHosts ? (
                                                            <button onClick={() => { setEditingHosts(true); setHostsForm(data.hosts || ''); }}
                                                                className="px-2 py-1 text-[11px]" style={{color: '#49afd9', border: '1px solid #485764'}}>{t('edit')}</button>
                                                        ) : (
                                                            <div className="flex gap-1">
                                                                <button onClick={() => setEditingHosts(false)} className="px-2 py-1 text-[11px]" style={{color: '#adbbc4', border: '1px solid #485764'}}>{t('cancel')}</button>
                                                                <button onClick={() => { handleSave('hosts', { data: hostsForm }, 'Hosts saved', 'POST'); setEditingHosts(false); }} disabled={saving}
                                                                    className="px-2 py-1 text-[11px]" style={{color: '#60b515', border: '1px solid rgba(96,181,21,0.3)'}}>{saving ? '...' : t('save')}</button>
                                                            </div>
                                                        )}
                                                    </div>
                                                    {editingHosts ? (
                                                        <textarea value={hostsForm} onChange={e => setHostsForm(e.target.value)} rows={8}
                                                            className="w-full px-3 py-2 text-[12px] bg-proxmox-dark border border-proxmox-border text-white font-mono" style={{resize: 'vertical'}} />
                                                    ) : (
                                                        <pre className="text-[12px] p-3 overflow-auto" style={{background: '#17242b', border: '1px solid #485764', color: '#adbbc4', fontFamily: 'monospace', maxHeight: '300px'}}>{data.hosts || 'No data'}</pre>
                                                    )}
                                                </div>
                                            )}
                                            {configSubTab === 'time' && (
                                                <div>
                                                    <span className="text-[13px] font-medium mb-3 block" style={{color: '#e9ecef'}}>{t('timeConfig')}</span>
                                                    <table className="corp-property-grid">
                                                        <tbody>
                                                            <tr><td>Timezone</td><td>{data.time?.timezone || '-'}</td></tr>
                                                            <tr><td>Local Time</td><td>{data.time?.localtime || '-'}</td></tr>
                                                            <tr><td>UTC Time</td><td>{data.time?.utctime || '-'}</td></tr>
                                                        </tbody>
                                                    </table>
                                                </div>
                                            )}
                                            {configSubTab === 'certs' && (
                                                <div>
                                                    <div className="flex items-center justify-between mb-3">
                                                        <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('certificates')}</span>
                                                        <button onClick={() => setShowCertUpload(!showCertUpload)}
                                                            className="px-2 py-1 text-[11px]" style={{color: '#49afd9', border: '1px solid #485764'}}>{showCertUpload ? t('cancel') : 'Upload'}</button>
                                                    </div>
                                                    {showCertUpload && (
                                                        <div className="mb-3 p-3 space-y-2" style={{background: '#17242b', border: '1px solid #485764'}}>
                                                            <div><label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>Certificate (PEM)</label><textarea value={certForm.cert} onChange={e => setCertForm({...certForm, cert: e.target.value})} rows={4} className="w-full px-2 py-1.5 text-[11px] bg-proxmox-dark border border-proxmox-border text-white font-mono" placeholder="-----BEGIN CERTIFICATE-----" /></div>
                                                            <div><label className="text-[11px] block mb-1" style={{color: '#728b9a'}}>Private Key (PEM)</label><textarea value={certForm.key} onChange={e => setCertForm({...certForm, key: e.target.value})} rows={4} className="w-full px-2 py-1.5 text-[11px] bg-proxmox-dark border border-proxmox-border text-white font-mono" placeholder="-----BEGIN PRIVATE KEY-----" /></div>
                                                            <label className="flex items-center gap-2 text-[12px]" style={{color: '#adbbc4'}}><input type="checkbox" checked={certForm.restart} onChange={e => setCertForm({...certForm, restart: e.target.checked})} /> Restart pveproxy after upload</label>
                                                            <button onClick={handleCertUpload} disabled={saving || !certForm.cert || !certForm.key}
                                                                className="px-3 py-1.5 text-[12px] disabled:opacity-40" style={{color: '#fff', background: '#49afd9', border: 'none'}}>{saving ? '...' : 'Upload Certificate'}</button>
                                                        </div>
                                                    )}
                                                    <table className="corp-datagrid">
                                                        <thead><tr><th>Filename</th><th>Subject</th><th>Issuer</th><th>Expires</th></tr></thead>
                                                        <tbody>
                                                            {(Array.isArray(data.certificates) ? data.certificates : []).map((cert, i) => (
                                                                <tr key={i}>
                                                                    <td>{cert.filename || '-'}</td>
                                                                    <td className="text-[11px]" style={{maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis'}}>{cert.subject || '-'}</td>
                                                                    <td className="text-[11px]" style={{maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis'}}>{cert.issuer || '-'}</td>
                                                                    <td>{cert.notafter ? new Date(cert.notafter * 1000).toLocaleDateString() : '-'}</td>
                                                                </tr>
                                                            ))}
                                                            {(!data.certificates || data.certificates.length === 0) && <tr><td colSpan={4} className="text-center py-4" style={{color: '#728b9a'}}>No certificates</td></tr>}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            )}
                                            {configSubTab === 'syslog' && (
                                                <div>
                                                    <div className="flex items-center justify-between mb-3">
                                                        <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('syslog')}</span>
                                                        <button onClick={() => loadTabData('system')} className="px-2 py-1 text-[11px] flex items-center gap-1" style={{color: '#49afd9', border: '1px solid #485764'}}>
                                                            <Icons.RefreshCw className="w-3 h-3" /> Refresh
                                                        </button>
                                                    </div>
                                                    <pre className="text-[11px] p-3 overflow-auto" style={{background: '#17242b', border: '1px solid #485764', color: '#adbbc4', fontFamily: 'monospace', maxHeight: '400px'}}>
                                                        {Array.isArray(data.syslog) ? data.syslog.map(l => l.t || l.n || l).join('\n') : (data.syslog || 'No data')}
                                                    </pre>
                                                </div>
                                            )}
                                            {configSubTab === 'disks' && (
                                                <div>
                                                    <span className="text-[13px] font-medium mb-3 block" style={{color: '#e9ecef'}}>{t('disks')}</span>
                                                    <table className="corp-datagrid">
                                                        <thead><tr><th>Device</th><th>{t('type')}</th><th>Size</th><th>{t('status')}</th></tr></thead>
                                                        <tbody>
                                                            {(Array.isArray(data.disks) ? data.disks : []).map((disk, i) => (
                                                                <tr key={i}>
                                                                    <td style={{fontFamily: 'monospace', fontSize: '12px'}}>{disk.devpath || '-'}</td>
                                                                    <td>{disk.type || '-'}</td>
                                                                    <td>{formatBytes(disk.size)}</td>
                                                                    <td>{disk.health || disk.used || '-'}</td>
                                                                </tr>
                                                            ))}
                                                            {(!data.disks || data.disks.length === 0) && <tr><td colSpan={4} className="text-center py-4" style={{color: '#728b9a'}}>No disks</td></tr>}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            )}
                                            {configSubTab === 'lvm' && (
                                                <div>
                                                    <span className="text-[13px] font-medium mb-3 block" style={{color: '#e9ecef'}}>{t('lvmStorage')}</span>
                                                    <table className="corp-datagrid">
                                                        <thead><tr><th>VG</th><th>Size</th><th>Free</th></tr></thead>
                                                        <tbody>
                                                            {(Array.isArray(data.lvm) ? data.lvm : []).map((vg, i) => (
                                                                <tr key={i}><td>{vg.vg || '-'}</td><td>{formatBytes(vg.size)}</td><td>{formatBytes(vg.free)}</td></tr>
                                                            ))}
                                                            {(!data.lvm || data.lvm.length === 0) && <tr><td colSpan={3} className="text-center py-4" style={{color: '#728b9a'}}>No LVM volumes</td></tr>}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            )}
                                            {configSubTab === 'lvmthin' && (
                                                <div>
                                                    <span className="text-[13px] font-medium mb-3 block" style={{color: '#e9ecef'}}>{t('lvmThinStorage')}</span>
                                                    <table className="corp-datagrid">
                                                        <thead><tr><th>Pool</th><th>VG</th><th>Size</th><th>Used</th></tr></thead>
                                                        <tbody>
                                                            {(Array.isArray(data.lvmthin) ? data.lvmthin : []).map((tp, i) => (
                                                                <tr key={i}><td>{tp.lv || '-'}</td><td>{tp.vg || '-'}</td><td>{formatBytes(tp.lv_size)}</td><td>{tp.metadata_usage ? `${(tp.metadata_usage * 100).toFixed(1)}%` : '-'}</td></tr>
                                                            ))}
                                                            {(!data.lvmthin || data.lvmthin.length === 0) && <tr><td colSpan={4} className="text-center py-4" style={{color: '#728b9a'}}>No LVM-Thin pools</td></tr>}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            )}
                                            {configSubTab === 'zfs' && (
                                                <div>
                                                    <span className="text-[13px] font-medium mb-3 block" style={{color: '#e9ecef'}}>{t('zfsStorage')}</span>
                                                    <table className="corp-datagrid">
                                                        <thead><tr><th>{t('name')}</th><th>Size</th><th>Free</th><th>Health</th></tr></thead>
                                                        <tbody>
                                                            {(Array.isArray(data.zfs) ? data.zfs : []).map((pool, i) => (
                                                                <tr key={i}><td>{pool.name || '-'}</td><td>{formatBytes(pool.size)}</td><td>{formatBytes(pool.free)}</td><td>{pool.health || '-'}</td></tr>
                                                            ))}
                                                            {(!data.zfs || data.zfs.length === 0) && <tr><td colSpan={4} className="text-center py-4" style={{color: '#728b9a'}}>No ZFS pools</td></tr>}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            )}
                                            {configSubTab === 'repos' && (
                                                <div>
                                                    <div className="flex items-center justify-between mb-3">
                                                        <span className="text-[13px] font-medium" style={{color: '#e9ecef'}}>{t('repositories')}</span>
                                                        <button onClick={async () => { const res = await authFetch(`${API_URL}/clusters/${clusterId}/nodes/${node}/repos/refresh`, { method: 'POST' }); addToast(res && res.ok ? 'apt update started' : 'Error', res && res.ok ? 'success' : 'error'); }}
                                                            className="px-2 py-1 text-[11px] flex items-center gap-1" style={{color: '#49afd9', border: '1px solid #485764'}}>
                                                            <Icons.RefreshCw className="w-3 h-3" /> apt update
                                                        </button>
                                                    </div>
                                                    <table className="corp-datagrid">
                                                        <thead><tr><th>{t('name')}</th><th>URI</th><th>{t('enabled')}</th><th>{t('actions')}</th></tr></thead>
                                                        <tbody>
                                                            {(Array.isArray(data.repos) ? data.repos : []).map((repo, i) => (
                                                                <tr key={i}>
                                                                    <td>{repo.Name || repo.Components?.join(', ') || '-'}</td>
                                                                    <td className="text-[11px] font-mono" style={{color: '#728b9a'}}>{repo.URIs?.join(', ') || '-'}</td>
                                                                    <td><span className={`corp-badge ${repo.Enabled ? 'corp-badge-online' : 'corp-badge-stopped'}`}>{repo.Enabled ? t('enabled') : t('disabled')}</span></td>
                                                                    <td>
                                                                        <button onClick={() => handleRepoToggle(repo)}
                                                                            className="px-2 py-0.5 text-[11px]"
                                                                            style={repo.Enabled ? {color: '#f54f47', border: '1px solid rgba(245,79,71,0.3)'} : {color: '#60b515', border: '1px solid rgba(96,181,21,0.3)'}}>
                                                                            {repo.Enabled ? t('disable') : t('enable')}
                                                                        </button>
                                                                    </td>
                                                                </tr>
                                                            ))}
                                                            {(!data.repos || data.repos.length === 0) && <tr><td colSpan={4} className="text-center py-4" style={{color: '#728b9a'}}>No repositories</td></tr>}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            )}
                                            {configSubTab === 'ceph' && (
                                                <div>
                                                    <span className="text-[13px] font-medium mb-3 block" style={{color: '#e9ecef'}}>Ceph</span>
                                                    {data.ceph && !data.ceph.available ? (
                                                        <div className="text-center py-8" style={{color: '#728b9a'}}><Icons.Database className="w-8 h-8 mx-auto mb-2 opacity-50" /><p className="text-[13px]">Ceph not configured on this node</p></div>
                                                    ) : (
                                                        <div className="space-y-3">
                                                            {data.ceph?.status && (
                                                                <table className="corp-property-grid">
                                                                    <tbody>
                                                                        <tr><td>Health</td><td style={{color: data.ceph.status.health?.status === 'HEALTH_OK' ? '#60b515' : '#efc006'}}>{data.ceph.status.health?.status || '-'}</td></tr>
                                                                        <tr><td>OSDs</td><td>{data.ceph.osd?.length || 0}</td></tr>
                                                                        <tr><td>MONs</td><td>{data.ceph.mon?.length || 0}</td></tr>
                                                                        <tr><td>Pools</td><td>{data.ceph.pools?.length || 0}</td></tr>
                                                                    </tbody>
                                                                </table>
                                                            )}
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* VMs Tab */}
                        {activeDetailTab === 'vms' && (
                            <div>
                                <span className="text-[13px] font-medium mb-3 block" style={{color: '#e9ecef'}}>{t('vmsOnNode')} ({nodeVms.length})</span>
                                <table className="corp-datagrid">
                                    <thead><tr><th>{t('name')}</th><th>VMID</th><th>{t('type')}</th><th>{t('status')}</th><th>CPU</th><th>{t('memory') || 'Memory'}</th></tr></thead>
                                    <tbody>
                                        {nodeVms.sort((a, b) => (a.name || '').localeCompare(b.name || '')).map(vm => (
                                            <tr key={vm.vmid} className="cursor-pointer" onClick={() => onSelectVm && onSelectVm(vm)}>
                                                <td className="flex items-center gap-1.5">
                                                    {vm.type === 'lxc'
                                                        ? <Icons.Box className="w-3 h-3" style={{color: vm.status === 'running' ? '#49afd9' : '#728b9a'}} />
                                                        : <Icons.Monitor className="w-3 h-3" style={{color: vm.status === 'running' ? '#60b515' : '#728b9a'}} />
                                                    }
                                                    <span style={{color: '#49afd9'}}>{vm.name || '-'}</span>
                                                </td>
                                                <td>{vm.vmid}</td>
                                                <td>{vm.type === 'qemu' ? 'QEMU' : 'LXC'}</td>
                                                <td><span className={`corp-badge ${vm.status === 'running' ? 'corp-badge-running' : 'corp-badge-stopped'}`}>{vm.status === 'running' ? t('running') : t('stopped')}</span></td>
                                                <td>{vm.maxcpu ? `${((vm.cpu || 0) * 100).toFixed(1)}%` : '-'}</td>
                                                <td>{vm.maxmem ? `${formatBytes(vm.mem)} / ${formatBytes(vm.maxmem)}` : '-'}</td>
                                            </tr>
                                        ))}
                                        {nodeVms.length === 0 && <tr><td colSpan={6} className="text-center py-4" style={{color: '#728b9a'}}>No VMs on this node</td></tr>}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {/* Shell Tab */}
                        {activeDetailTab === 'shell' && (
                            <div className="bg-black border border-proxmox-border overflow-hidden" style={{height: '500px'}}>
                                <NodeShellTerminal node={node} clusterId={clusterId} addToast={addToast} />
                            </div>
                        )}

                        {/* Subscription Tab */}
                        {activeDetailTab === 'subscription' && (
                            <div>
                                <span className="text-[13px] font-medium mb-3 block" style={{color: '#e9ecef'}}>{t('subscriptionInfo')}</span>
                                {loading && !data.subscription ? (
                                    <div className="flex items-center justify-center h-32"><Icons.RotateCw className="w-5 h-5 animate-spin" style={{color: '#49afd9'}} /></div>
                                ) : (
                                    <table className="corp-property-grid">
                                        <tbody>
                                            <tr><td>{t('status')}</td><td style={{color: data.subscription?.status === 'Active' ? '#60b515' : data.subscription?.status === 'notfound' ? '#728b9a' : '#efc006'}}>{data.subscription?.status || 'No subscription'}</td></tr>
                                            <tr><td>Server ID</td><td style={{fontFamily: 'monospace', fontSize: '12px'}}>{data.subscription?.serverid || '-'}</td></tr>
                                            <tr><td>Product</td><td>{data.subscription?.productname || '-'}</td></tr>
                                            <tr><td>Key</td><td style={{fontFamily: 'monospace', fontSize: '12px'}}>{data.subscription?.key || '-'}</td></tr>
                                            <tr><td>Next Due</td><td>{data.subscription?.nextduedate || '-'}</td></tr>
                                        </tbody>
                                    </table>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            );
        }

