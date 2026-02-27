        // ═══════════════════════════════════════════════
        // PegaProx - UI Components
        // Charts, Gauge, Toast, NodeJoin wizards
        // ═══════════════════════════════════════════════

        // Sparkline Component - Small inline chart
        // NS: ChatGPT wrote the initial SVG math, I just cleaned it up
        function Sparkline({ data = [], color = '#3b82f6', height = 24, width = 80 }) {
            if (!data || data.length === 0) return null;
            
            const max = Math.max(...data, 1);
            const min = Math.min(...data, 0);
            const range = max - min || 1;
            
            const points = data.map((value, index) => {
                const x = (index / (data.length - 1)) * width;
                const y = height - ((value - min) / range) * height;
                return `${x},${y}`;
            }).join(' ');
            
            return(
                <svg width={width} height={height} className="inline-block">
                    <polyline
                        fill="none"
                        stroke={color}
                        strokeWidth="1.5"
                        points={points}
                    />
                </svg>
            );
        }

        // VM Metrics Modal - Shows detailed graphs
        // LW: RRD data from Proxmox, charts built with SVG
        // Oct 2025: Added timeframe selector after user feedback
        // Helper functions moved outside component
        const formatBytes = (bytes) => {
            if (bytes === 0) return '0 B';
            if (!bytes || isNaN(bytes)) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            if (bytes < 1) return bytes.toFixed(2) + ' B';

            const i = Math.floor(Math.log(bytes) / Math.log(k));
            if (i < 0) return bytes.toFixed(1) + ' B';
            if (i >= sizes.length) return (bytes / Math.pow(k, sizes.length - 1)).toFixed(1) + ' ' + sizes[sizes.length - 1];

            return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
        };

        const formatTime = (ts) => {
            if (!ts) return '';
            return new Date(ts * 1000).toLocaleString();
        };

        // Chart.js line chart component - uses canvas for interactive charts
        const LineChart = React.memo(function LineChart({ data, datasets, timestamps, label, color, unit, formatValue, yMin, yMax }) {
            const canvasRef = React.useRef(null);
            const chartRef = React.useRef(null);
            const formatRef = React.useRef(formatValue);
            formatRef.current = formatValue;

            // Normalize input to array of datasets
            const chartDatasets = React.useMemo(() => {
                if (datasets && datasets.length > 0) return datasets.filter(ds => ds.data && ds.data.length > 0);
                if (data && data.length > 0) return [{ label: label, data: data, color: color, fill: true }];
                return [];
            }, [data, datasets, label, color]);

            // Stable fingerprint of data to avoid re-creating chart on parent re-renders
            const dataFingerprint = React.useMemo(() => {
                if (chartDatasets.length === 0) return '';
                // Simple fingerprint: length + first + middle + last values of all datasets
                return chartDatasets.map(ds => {
                    const d = ds.data;
                    if (!d || d.length === 0) return '0';
                    return d.length + ':' + (d[0] || 0) + ':' + (d[Math.floor(d.length/2)] || 0) + ':' + (d[d.length-1] || 0);
                }).join('|');
            }, [chartDatasets]);

            // Cleanup on unmount
            React.useEffect(() => {
                return () => {
                    if (chartRef.current) {
                        chartRef.current.destroy();
                        chartRef.current = null;
                    }
                };
            }, []);

            // Create/update chart only when data actually changes
            React.useEffect(() => {
                if (!canvasRef.current || !window.Chart) return;

                // Destroy previous chart
                if (chartRef.current) {
                    chartRef.current.destroy();
                    chartRef.current = null;
                }

                if (chartDatasets.length === 0) return;

                // Process datasets (sanitize and decimate)
                const processedDatasets = [];
                let finalLabels = [];

                // Determine timestamps/labels from first valid dataset or timestamps prop
                const rawLength = (chartDatasets[0] && chartDatasets[0].data) ? chartDatasets[0].data.length : 0;
                if (rawLength === 0) return;

                // Build raw labels first
                const rawLabels = [];
                if (timestamps && timestamps.length === rawLength) {
                    for (let i = 0; i < timestamps.length; i++) {
                        const d = new Date(timestamps[i] * 1000);
                        rawLabels.push(d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
                    }
                } else {
                    for (let i = 0; i < rawLength; i++) {
                        rawLabels.push(String(i));
                    }
                }

                // Decimation factor
                const step = rawLength > 200 ? Math.ceil(rawLength / 200) : 1;

                // Process labels
                if (step > 1) {
                    for (let i = 0; i < rawLength; i += step) {
                        finalLabels.push(rawLabels[i]);
                    }
                } else {
                    finalLabels = rawLabels;
                }

                // Process each dataset
                chartDatasets.forEach(ds => {
                    if (!ds.data || ds.data.length === 0) return;
                    const cleanData = [];
                    for (let i = 0; i < ds.data.length; i++) {
                        const v = ds.data[i];
                        cleanData.push((v === null || v === undefined || v !== v) ? 0 : v);
                    }

                    let finalData = [];
                    if (step > 1) {
                        for (let i = 0; i < cleanData.length; i += step) {
                            finalData.push(cleanData[i]);
                        }
                    } else {
                        finalData = cleanData;
                    }

                    processedDatasets.push({
                        label: ds.label || label,
                        data: finalData,
                        borderColor: ds.color || color,
                        backgroundColor: (ds.color || color) + '33',
                        fill: ds.fill !== undefined ? ds.fill : true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHitRadius: 8,
                        borderWidth: 2,
                    });
                });

                // Set canvas dimensions explicitly
                const canvas = canvasRef.current;
                const parent = canvas.parentElement;
                if (parent) {
                    canvas.width = parent.clientWidth || 600;
                    canvas.height = 180;
                }

                const unitStr = unit || '%';
                const ctx = canvas.getContext('2d');

                try {
                    const chart = new window.Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: finalLabels,
                            datasets: processedDatasets
                        },
                        options: {
                            responsive: false,
                            animation: false,
                            normalized: true,
                            interaction: {
                                mode: 'nearest',
                                axis: 'x',
                                intersect: false,
                            },
                            plugins: {
                                legend: {
                                    display: processedDatasets.length > 1,
                                    labels: { color: '#9ca3af', usePointStyle: true, boxWidth: 6 }
                                },
                                tooltip: {
                                    enabled: true,
                                    mode: 'index',
                                    intersect: false,
                                    backgroundColor: 'rgba(30, 30, 40, 0.95)',
                                    titleColor: '#e5e7eb',
                                    bodyColor: '#fff',
                                    callbacks: {
                                        label: function(c) {
                                            var val = c.parsed.y;
                                            var fn = formatRef.current;
                                            var str = fn ? fn(val) : val.toFixed(2);
                                            return ' ' + c.dataset.label + ': ' + str + (unitStr.trim() ? unitStr : '');
                                        }
                                    }
                                },
                                decimation: false,
                            },
                            scales: {
                                x: {
                                    ticks: {
                                        color: '#6b7280',
                                        font: { size: 10 },
                                        maxTicksLimit: 8,
                                        maxRotation: 0,
                                    },
                                    grid: { color: 'rgba(75, 85, 99, 0.3)' }
                                },
                                y: {
                                    beginAtZero: true,
                                    min: yMin,
                                    max: yMax,
                                    ticks: {
                                        color: '#6b7280',
                                        font: { size: 10 },
                                        callback: function(value) {
                                            var fn = formatRef.current;
                                            if (fn) return fn(value) + (unitStr.trim() ? unitStr : '');
                                            return value.toFixed(yMax && yMax <= 10 ? 1 : 0) + unitStr;
                                        }
                                    },
                                    grid: { color: 'rgba(75, 85, 99, 0.3)' }
                                }
                            }
                        }
                    });
                    chartRef.current = chart;
                } catch(e) {
                    console.error('Chart.js error for ' + label + ':', e);
                }
            }, [dataFingerprint, unit, yMin, yMax]); // re-run if data changes

            if (chartDatasets.length === 0) return null;

            return(
                React.createElement('div', { className: 'bg-proxmox-dark rounded-lg p-4' },
                    React.createElement('div', { className: 'flex justify-between items-center mb-2' },
                        React.createElement('span', { className: 'text-sm font-medium text-gray-300' }, label),
                    ),
                    React.createElement('div', { style: { width: '100%', height: '180px' } },
                        React.createElement('canvas', { ref: canvasRef })
                    )
                )
            );
        });

        function VmMetricsModal({ vm, clusterId, onClose }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [timeframe, setTimeframe] = useState('day');
            const [loading, setLoading] = useState(true);
            const [data, setData] = useState(null);
            const [err, setErr] = useState(null);
            
            // LW: one-liner, keep it simple
            const authFetch = (url, opts = {}) => fetch(url, { ...opts, credentials: 'include', headers: { ...opts.headers, ...getAuthHeaders() } });
            
            useEffect(() => {
                const fetchMetrics = async () => {
                    setLoading(true);
                    setErr(null);
                    try {
                        const r = await authFetch(
                            `${API_URL}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/rrd/${timeframe}`
                        );
                        if (r.ok) {
                            setData(await r.json());
                        }else{
                            setErr('Failed to load metrics');
                        }
                    } catch (e) {
                        setErr(e.message);
                    }
                    setLoading(false);
                };
                fetchMetrics();
            }, [timeframe, vm.vmid]);
            // Prepare memory data in GB
            const maxMemGB = vm.maxmem ? vm.maxmem / (1024 * 1024 * 1024) : 0;
            const memDataGB = React.useMemo(() => {
                if (!data || !data.metrics || !data.metrics.memory || !maxMemGB) return [];
                return data.metrics.memory.map(p => (p / 100) * maxMemGB);
            }, [data, maxMemGB]);

            return(
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-4xl max-h-[90vh] overflow-hidden" onClick={e => e.stopPropagation()}>
                        <div className="flex justify-between items-center p-4 border-b border-proxmox-border">
                            <div>
                                <h2 className="text-lg font-semibold text-white">
                                    {vm.name || `${vm.type === 'qemu' ? 'VM' : 'CT'} ${vm.vmid}`} - {t('performanceMetrics') || 'Performance Metrics'}
                                </h2>
                                <p className="text-sm text-gray-500">Node: {vm.node}</p>
                            </div>
                            <div className="flex items-center gap-4">
                                <select
                                    value={timeframe}
                                    onChange={e => setTimeframe(e.target.value)}
                                    className="bg-proxmox-dark border border-proxmox-border rounded px-3 py-1.5 text-sm text-white"
                                >
                                    <option value="hour">1 {t('hour') || 'Hour'}</option>
                                    <option value="day">1 {t('day') || 'Day'}</option>
                                    <option value="week">1 {t('week') || 'Week'}</option>
                                    <option value="month">1 {t('month') || 'Month'}</option>
                                    <option value="year">1 {t('year') || 'Year'}</option>
                                </select>
                                <button onClick={onClose} className="p-1 hover:bg-proxmox-border rounded">
                                    <Icons.X />
                                </button>
                            </div>
                        </div>
                        
                        <div className="p-4 overflow-y-auto max-h-[70vh]">
                            {loading ? (
                                <div className="flex items-center justify-center py-12">
                                    <Icons.RotateCw />
                                    <span className="ml-2 text-gray-400">{t('loading') || 'Loading...'}</span>
                                </div>
                            ) : err ? (
                                <div className="text-center py-12 text-red-400">{err}</div>
                            ) : data && data.metrics ? (
                                <div className="space-y-4">
                                    <LineChart 
                                        data={data.metrics.cpu}
                                        timestamps={data.timestamps}
                                        label="CPU" 
                                        color="#3b82f6" 
                                        unit="%" 
                                    />
                                    <LineChart 
                                        data={memDataGB}
                                        timestamps={data.timestamps}
                                        label="Memory" 
                                        color="#22c55e" 
                                        unit=" GB"
                                        yMin={0}
                                        yMax={maxMemGB}
                                        formatValue={(v) => v.toFixed(2)}
                                    />
                                    <div className="grid grid-cols-2 gap-4">
                                        <LineChart 
                                            data={data.metrics.disk_read}
                                            timestamps={data.timestamps}
                                            label="Disk Read" 
                                            color="#eab308" 
                                            unit="/s"
                                            formatValue={formatBytes}
                                        />
                                        <LineChart 
                                            data={data.metrics.disk_write}
                                            timestamps={data.timestamps}
                                            label="Disk Write" 
                                            color="#f97316" 
                                            unit="/s"
                                            formatValue={formatBytes}
                                        />
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <LineChart 
                                            data={data.metrics.net_in}
                                            timestamps={data.timestamps}
                                            label="Network In" 
                                            color="#06b6d4" 
                                            unit="/s"
                                            formatValue={formatBytes}
                                        />
                                        <LineChart 
                                            data={data.metrics.net_out}
                                            timestamps={data.timestamps}
                                            label="Network Out" 
                                            color="#8b5cf6" 
                                            unit="/s"
                                            formatValue={formatBytes}
                                        />
                                    </div>

                                    {data.metrics.pressurecpusome && (
                                        <LineChart
                                            datasets={[
                                                { label: 'Some', data: data.metrics.pressurecpusome, color: '#3b82f6' },
                                                { label: 'Full', data: data.metrics.pressurecpufull, color: '#ef4444' }
                                            ]}
                                            timestamps={data.timestamps}
                                            label="CPU Pressure Stall"
                                            unit="%"
                                            yMin={0}
                                            yMax={100}
                                        />
                                    )}
                                    {data.metrics.pressurememorysome && (
                                        <LineChart
                                            datasets={[
                                                { label: 'Some', data: data.metrics.pressurememorysome, color: '#22c55e' },
                                                { label: 'Full', data: data.metrics.pressurememoryfull, color: '#ef4444' }
                                            ]}
                                            timestamps={data.timestamps}
                                            label="Memory Pressure Stall"
                                            unit="%"
                                            yMin={0}
                                            yMax={100}
                                        />
                                    )}
                                    {data.metrics.pressureiosome && (
                                        <LineChart
                                            datasets={[
                                                { label: 'Some', data: data.metrics.pressureiosome, color: '#eab308' },
                                                { label: 'Full', data: data.metrics.pressureiofull, color: '#ef4444' }
                                            ]}
                                            timestamps={data.timestamps}
                                            label="IO Pressure Stall"
                                            unit="%"
                                            yMin={0}
                                            yMax={100}
                                        />
                                    )}
                                    
                                    {data.timestamps && data.timestamps.length > 0 && (
                                        <div className="text-xs text-gray-500 text-center mt-4">
                                            {formatTime(data.timestamps[0])} - {formatTime(data.timestamps[data.timestamps.length - 1])}
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div className="text-center py-12 text-gray-400">No data available</div>
                            )}
                        </div>
                    </div>
                </div>
            );
        }
        // Gauge Component
        function Gauge({ value, max = 100, size = 120, label, color }) {
            const r = 45;
            const circ = 2 * Math.PI * r;
            const prog = Math.min(value / max, 1);
            const off = circ - (prog * circ);
            
            // color thresholds
            const getColor = () => {
                if (color) return color;
                if (value < 50) return '#22c55e';  // green
                if (value < 80) return '#eab308';  // yellow
                return '#ef4444';  // red
            };

            return(
                <div className="gauge-container flex flex-col items-center">
                    <svg viewBox="0 0 100 100" className="w-full h-full">
                        <circle cx="50" cy="50" r={r} className="gauge-bg" />
                        <circle 
                            cx="50" 
                            cy="50" 
                            r={r} 
                            className="gauge-fill"
                            style={{
                                stroke: getColor(),
                                strokeDasharray: circ,
                                strokeDashoffset: off,
                            }}
                        />
                        <text x="50" y="50" textAnchor="middle" dy="0.35em" className="gauge-text text-white text-lg">
                            {value.toFixed(1)}%
                        </text>
                    </svg>
                    <span className="text-xs text-gray-400 mt-1 font-medium">{label}</span>
                </div>
            );
        }

        /*
         * Toggle Component
         * NS: simple on/off switch, used everywhere
         */
        function Toggle({ checked, onChange, label }) {
            return(
                <label className="flex items-center gap-3 cursor-pointer group">
                    <div className={`toggle-switch ${checked ? 'active' : ''}`} onClick={() => onChange(!checked)} />
                    <span className="text-sm text-gray-300 group-hover:text-white transition-colors">{label}</span>
                </label>
            );
        }

        // Slider Component - LW: fancy slider with gradient fill
        function Slider({ label, value, onChange, min = 0, max = 100, step = 1, unit = '%', description }) {
            const percentage = ((value - min) / (max - min)) * 100;
            
            return(
                <div className="space-y-3">
                    <div className="flex justify-between items-center">
                        <div>
                            <label className="text-sm font-medium text-gray-200">{label}</label>
                            {description && <p className="text-xs text-gray-500">{description}</p>}
                        </div>
                        <span className="font-mono text-sm text-proxmox-orange font-semibold bg-proxmox-orange/10 px-3 py-1 rounded-lg">
                            {value}{unit}
                        </span>
                    </div>
                    <div className="relative">
                        <div className="absolute inset-0 h-2 rounded-full bg-proxmox-border top-1/2 -translate-y-1/2" />
                        <div 
                            className="absolute h-2 rounded-full bg-gradient-to-r from-proxmox-orange to-orange-400 top-1/2 -translate-y-1/2 transition-all"
                            style={{ width: `${percentage}%` }}
                        />
                        <input
                            type="range"
                            min={min}
                            max={max}
                            step={step}
                            value={value}
                            onChange={(e) => onChange(Number(e.target.value))}
                            className="custom-slider w-full relative z-10 bg-transparent"
                        />
                    </div>
                    <div className="flex justify-between text-xs text-gray-500">
                        <span>{min}{unit}</span>
                        <span>{max}{unit}</span>
                    </div>
                </div>
            );
        }

        // Sponsor Slot Component - loads PNG from /images/sponsors/
        function SponsorSlot({ num }) {
            const { t } = useTranslation();
            const [hasImage, setHasImage] = useState(true);
            const [sponsorUrl, setSponsorUrl] = useState(null);
            
            // Sponsor URLs - edit these to add sponsor links
            const sponsorLinks = {
                1: 'https://socialfurr.com',
                2: null,
                3: null,
                4: null,
                5: null,
                6: null,
                7: null,
                8: null
            };
            
            const handleImageError = () => {
                setHasImage(false);
            };
            
            const url = sponsorLinks[num];
            const imageSrc = `/images/sponsors/sponsor${num}.png`;
            
            if (!hasImage) {
                // Show "Wanted" placeholder
                return(
                    <a 
                        href="mailto:sponsor@pegaprox.com?subject=Sponsorship%20Inquiry" 
                        className="group"
                        title={t('becomeSponsor') || 'Become a sponsor'}
                    >
                        <div className="w-12 h-12 rounded-lg bg-proxmox-card border border-dashed border-proxmox-border flex flex-col items-center justify-center hover:border-proxmox-orange/50 transition-all hover:scale-105">
                            <span className="text-sm">🎯</span>
                        </div>
                    </a>
                );
            }
            
            const content = (
                <div className="w-12 h-12 rounded-lg bg-proxmox-card border border-proxmox-border p-1 flex items-center justify-center hover:border-proxmox-orange/50 transition-all hover:scale-105 overflow-hidden">
                    <img 
                        src={imageSrc}
                        alt={`Sponsor ${num}`}
                        className="w-full h-full object-contain opacity-80 group-hover:opacity-100 transition-opacity"
                        onError={handleImageError}
                    />
                </div>
            );
            
            if (url) {
                return(
                    <a href={url} target="_blank" rel="noopener noreferrer" className="group">
                        {content}
                    </a>
                );
            }
            
            return <div className="group">{content}</div>;
        }

        // Notification Toast
        // LW: Simple toast - auto-closes after 3s
        // tried 5s but users complained it was too long
        function Toast({ message, type = 'success', onClose }) {
            useEffect(() => {
                const timer = setTimeout(onClose, 3000);  // 3000ms = 3s
                return() => clearTimeout(timer);
            }, [onClose]);

            // NS: ternary hell but it works lol
            return(
                <div className={`toast-enter flex items-center gap-3 px-4 py-3 rounded-lg border ${
                    type === 'success' 
                        ? 'bg-green-500/10 border-green-500/30 text-green-400' 
                        : type === 'error'
                        ? 'bg-red-500/10 border-red-500/30 text-red-400'
                        : 'bg-proxmox-orange/10 border-proxmox-orange/30 text-proxmox-orange'
                }`}>
                    {type === 'success' ? <Icons.Check /> : type === 'error' ? <Icons.X /> : <Icons.Activity />}
                    <span className="text-sm font-medium">{message}</span>
                </div>
            );
        }

        // Node Alert Banner - shows critical alerts when nodes go offline
        // fix for #184 - banner was not showing on first load
        // NS: Now filters by cluster_id to only show alerts for current cluster
        function NodeAlertBanner({ alerts, onDismiss, currentClusterId }) {
            const { t } = useTranslation();
            
            // Filter alerts to only show ones for the current cluster
            const alertEntries = Object.entries(alerts || {})
                .filter(([nodeName, alert]) => !currentClusterId || alert.cluster_id === currentClusterId);
            
            if (alertEntries.length === 0) return null;
            
            return(
                <div className="fixed top-0 left-0 right-0 z-50">
                    {alertEntries.map(([nodeName, alert]) => (
                        <div 
                            key={nodeName}
                            className="bg-red-600 text-white px-4 py-3 flex items-center justify-between animate-pulse"
                        >
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-red-500 rounded-full">
                                    <Icons.AlertTriangle className="w-5 h-5" />
                                </div>
                                <div>
                                    <span className="font-bold">{t('criticalAlert') || 'CRITICAL ALERT'}:</span>
                                    <span className="ml-2">{alert.message}</span>
                                    <span className="ml-4 text-red-200 text-sm">
                                        {new Date(alert.timestamp).toLocaleTimeString()}
                                    </span>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="text-sm text-red-200">
                                    {t('haRecoveryMayStart') || 'HA recovery may be in progress...'}
                                </span>
                                <button
                                    onClick={() => onDismiss && onDismiss(nodeName)}
                                    className="p-1 hover:bg-red-500 rounded"
                                    title={t('dismiss') || 'Dismiss'}
                                >
                                    <Icons.X className="w-4 h-4" />
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            );
        }

        // =============================================================================
        // NODE MANAGEMENT COMPONENTS
        // NS: Feb 2026 - 3-step join wizard: test connection ↑ verify info ↑ join
        // LW: Force rejoin option handles nodes removed via pvecm delnode
        // MK: Uses invoke_shell for pvecm add because it prompts for password interactively
        // =============================================================================
        function NodeJoinWizard({ isOpen, onClose, clusterId, onSuccess, addToast }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [step, setStep] = useState(1);
            const [loading, setLoading] = useState(false);
            const [error, setError] = useState(null);
            const [nodeIp, setNodeIp] = useState('');
            const [username, setUsername] = useState('root');
            const [password, setPassword] = useState('');
            const [sshPort, setSshPort] = useState(22);
            const [link0Address, setLink0Address] = useState('');
            const [nodeInfo, setNodeInfo] = useState(null);
            const [joinResult, setJoinResult] = useState(null);
            const [forceRejoin, setForceRejoin] = useState(false);
            
            const resetWizard = () => { setStep(1); setNodeIp(''); setUsername('root'); setPassword(''); setSshPort(22); setLink0Address(''); setNodeInfo(null); setJoinResult(null); setError(null); setLoading(false); };
            const handleClose = () => { resetWizard(); onClose(); };
            
            const testConnection = async () => {
                setLoading(true); setError(null);
                try {
                    const response = await fetch(`${API_URL}/clusters/${clusterId}/nodes/join/test`, {
                        method: 'POST', 
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify({ node_ip: nodeIp, username, password, ssh_port: sshPort })
                    });
                    const data = await response.json();
                    if (data.success) { 
                        setNodeInfo(data.info); 
                        if (data.info.already_in_cluster || data.info.has_old_config) setForceRejoin(true);
                        setStep(2); 
                    } else { setError(data.error || 'Connection failed'); }
                } catch (err) { setError('Network error: ' + err.message); }
                finally { setLoading(false); }
            };
            
            const joinCluster = async () => {
                setLoading(true); setError(null);
                try {
                    const response = await fetch(`${API_URL}/clusters/${clusterId}/nodes/join`, {
                        method: 'POST', 
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify({ node_ip: nodeIp, username, password, ssh_port: sshPort, link0_address: link0Address || undefined, force: forceRejoin })
                    });
                    const data = await response.json();
                    if (data.success) { setJoinResult(data); setStep(3); if (onSuccess) onSuccess(); } else { setError(data.error || 'Join failed'); }
                } catch (err) { setError('Network error: ' + err.message); }
                finally { setLoading(false); }
            };
            
            if (!isOpen) return null;
            return (
                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-lg">
                        <div className="p-4 border-b border-proxmox-border flex justify-between items-center">
                            <h2 className="text-lg font-semibold flex items-center gap-2"><Icons.Server className="w-5 h-5 text-proxmox-orange" />Add Node to Cluster</h2>
                            <button onClick={handleClose} className="p-1 hover:bg-proxmox-dark rounded"><Icons.X className="w-5 h-5" /></button>
                        </div>
                        <div className="px-4 py-3 border-b border-proxmox-border">
                            <div className="flex items-center justify-between">
                                {[1, 2, 3].map(s => (<div key={s} className="flex items-center"><div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${step >= s ? 'bg-proxmox-orange text-white' : 'bg-proxmox-dark text-gray-400'}`}>{step > s ? <Icons.Check className="w-4 h-4" /> : s}</div><span className={`ml-2 text-sm ${step >= s ? 'text-white' : 'text-gray-500'}`}>{s === 1 ? 'Connect' : s === 2 ? 'Verify' : 'Join'}</span>{s < 3 && <div className="w-12 h-0.5 bg-proxmox-border mx-2" />}</div>))}
                            </div>
                        </div>
                        <div className="p-4">
                            {error && <div className="mb-4 p-3 bg-red-500/20 border border-red-500 rounded-lg text-red-400 text-sm">{error}</div>}
                            {step === 1 && (<div className="space-y-4">
                                <div><label className="block text-sm text-gray-400 mb-1">Node IP *</label><input type="text" value={nodeIp} onChange={e => setNodeIp(e.target.value)} placeholder="192.168.1.100" className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white" /></div>
                                <div className="grid grid-cols-2 gap-4"><div><label className="block text-sm text-gray-400 mb-1">SSH User</label><input type="text" value={username} onChange={e => setUsername(e.target.value)} className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white" /></div><div><label className="block text-sm text-gray-400 mb-1">SSH Port</label><input type="number" value={sshPort} onChange={e => setSshPort(parseInt(e.target.value) || 22)} className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white" /></div></div>
                                <div><label className="block text-sm text-gray-400 mb-1">SSH Password *</label><input type="password" value={password} onChange={e => setPassword(e.target.value)} className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white" /></div>
                                <div><label className="block text-sm text-gray-400 mb-1">Link0 Address (optional)</label><input type="text" value={link0Address} onChange={e => setLink0Address(e.target.value)} placeholder="10.0.0.100" className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white" /><p className="text-xs text-gray-500 mt-1">Only for multi-network setups</p></div>
                            </div>)}
                            {step === 2 && nodeInfo && (<div className="space-y-4">
                                <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg"><div className="flex items-center gap-2 text-green-400"><Icons.CheckCircle className="w-5 h-5" /><span className="font-medium">Connection OK</span></div></div>
                                <div className="bg-proxmox-dark rounded-lg p-4 space-y-3">
                                    <div className="flex justify-between"><span className="text-gray-400">Hostname:</span><span className="font-mono text-white">{nodeInfo.hostname}</span></div>
                                    <div className="flex justify-between"><span className="text-gray-400">IP:</span><span className="font-mono text-white">{nodeInfo.ip}</span></div>
                                    <div className="flex justify-between"><span className="text-gray-400">Proxmox:</span><span className={nodeInfo.proxmox_installed ? 'text-green-400' : 'text-red-400'}>{nodeInfo.proxmox_installed ? nodeInfo.proxmox_version : 'Not Installed'}</span></div>
                                    <div className="flex justify-between"><span className="text-gray-400">Cluster:</span><span className={nodeInfo.already_in_cluster ? 'text-yellow-400' : 'text-green-400'}>{nodeInfo.already_in_cluster ? nodeInfo.current_cluster : 'Not in cluster'}</span></div>
                                </div>
                                {!nodeInfo.proxmox_installed && <div className="p-3 bg-red-500/20 border border-red-500 rounded-lg text-red-400 text-sm">Proxmox VE not installed</div>}
                                {(nodeInfo.already_in_cluster || nodeInfo.has_old_config) && (
                                    <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm flex items-start gap-2">
                                        <Icons.AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                                        <span>{nodeInfo.already_in_cluster ? 'This node is already in a cluster.' : 'This node has leftover cluster config files.'}</span>
                                    </div>
                                )}
                                {nodeInfo.proxmox_installed && (
                                    <label className="flex items-center gap-2 cursor-pointer p-3 bg-proxmox-dark rounded-lg border border-proxmox-border">
                                        <input type="checkbox" checked={forceRejoin} onChange={e => setForceRejoin(e.target.checked)} className="w-4 h-4 rounded border-gray-500 accent-proxmox-orange" />
                                        <span className="text-sm text-white font-medium">Force Join</span>
                                        <span className="text-xs text-gray-500">- cleans old corosync/pve config before joining (use if node was previously in a cluster)</span>
                                    </label>
                                )}
                            </div>)}
                            {step === 3 && joinResult && (<div className="text-center"><div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg"><Icons.CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-2" /><h3 className="text-lg font-semibold text-green-400">Node Joined!</h3><p className="text-gray-400 mt-2">{joinResult.message}</p></div><p className="text-sm text-gray-500 mt-4">Refresh to see the new node.</p></div>)}
                        </div>
                        <div className="p-4 border-t border-proxmox-border flex justify-between">
                            {step === 1 && (<><button onClick={handleClose} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-border rounded-lg text-white">Cancel</button><button onClick={testConnection} disabled={loading || !nodeIp || !password} className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg disabled:opacity-50 flex items-center gap-2 text-white">{loading && <Icons.Loader className="w-4 h-4 animate-spin" />}Test Connection</button></>)}
                            {step === 2 && (<><button onClick={() => setStep(1)} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-border rounded-lg text-white">Back</button><button onClick={joinCluster} disabled={loading || !nodeInfo?.proxmox_installed || (nodeInfo?.already_in_cluster && !forceRejoin)} className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg disabled:opacity-50 flex items-center gap-2 text-white">{loading && <Icons.Loader className="w-4 h-4 animate-spin" />}{loading ? 'Joining...' : (forceRejoin ? 'Force Join Cluster' : 'Join Cluster')}</button></>)}
                            {step === 3 && <button onClick={handleClose} className="px-4 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg ml-auto text-white">Done</button>}
                        </div>
                    </div>
                </div>
            );
        }

        // MK: Feb 2026 - Removal checklist with blockers (hard) vs warnings (soft)
        // LW: After pvecm delnode, automatically cleans up stale config on removed node via SSH
        function RemoveNodeConfirmModal({ isOpen, onClose, node, clusterId, onSuccess, addToast }) {
            const { getAuthHeaders } = useAuth();
            const [loading, setLoading] = useState(false);
            const [error, setError] = useState(null);
            const [canRemove, setCanRemove] = useState(null);
            const [confirmText, setConfirmText] = useState('');
            
            useEffect(() => {
                if (isOpen && node) {
                    setConfirmText(''); setError(null); setCanRemove(null);
                    fetch(`${API_URL}/clusters/${clusterId}/nodes/${node.name}/can-remove`, { 
                        credentials: 'include',
                        headers: getAuthHeaders() 
                    })
                        .then(r => {
                            if (!r.ok) throw new Error(`HTTP ${r.status}`);
                            return r.json();
                        })
                        .then(setCanRemove)
                        .catch(e => setError('Could not check status: ' + e.message));
                }
            }, [isOpen, node]);
            
            const removeNode = async () => {
                if (confirmText !== node.name) return;
                setLoading(true); setError(null);
                try {
                    const response = await fetch(`${API_URL}/clusters/${clusterId}/nodes/${node.name}/cluster-membership`, {
                        method: 'DELETE', credentials: 'include', headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify({ confirm: true })
                    });
                    const data = await response.json();
                    if (data.success) { 
                        const cleanupOk = data.cleanup?.success;
                        const cleanupDetail = data.cleanup?.message || '';
                        const cleanupMsg = cleanupOk ? ' ✓ Config cleaned' : ` ⚠ Cleanup: ${cleanupDetail}`;
                        if (addToast) addToast(`Node removed.${cleanupMsg}`, cleanupOk ? 'success' : 'warning'); 
                        if (onSuccess) onSuccess(); onClose(); 
                    }
                    else { setError(data.error || 'Failed'); }
                } catch (err) { setError('Network error'); }
                finally { setLoading(false); }
            };
            
            if (!isOpen || !node) return null;
            return (
                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-md">
                        <div className="p-4 border-b border-proxmox-border"><h2 className="text-lg font-semibold text-red-400 flex items-center gap-2"><Icons.AlertTriangle className="w-5 h-5" />Remove Node</h2></div>
                        <div className="p-4 space-y-4">
                            {error && <div className="p-3 bg-red-500/20 border border-red-500 rounded-lg text-red-400 text-sm">{error}</div>}
                            <p className="text-gray-300">Remove <strong className="text-white">{node.name}</strong> from cluster?</p>
                            <p className="text-xs text-gray-500">This runs <code className="bg-proxmox-dark px-1 rounded">pvecm delnode</code> on another cluster node.</p>
                            {canRemove && (<div className="bg-proxmox-dark rounded-lg p-3 space-y-2">
                                <div className="flex items-center gap-2">{canRemove.in_maintenance ? <Icons.CheckCircle className="w-4 h-4 text-green-400" /> : <Icons.XCircle className="w-4 h-4 text-red-400" />}<span className={canRemove.in_maintenance ? 'text-green-400' : 'text-red-400'}>Maintenance Mode</span></div>
                                <div className="flex items-center gap-2">{canRemove.maintenance_complete ? <Icons.CheckCircle className="w-4 h-4 text-green-400" /> : <Icons.XCircle className="w-4 h-4 text-red-400" />}<span className={canRemove.maintenance_complete ? 'text-green-400' : 'text-red-400'}>Evacuation Done</span></div>
                                <div className="flex items-center gap-2">{canRemove.is_offline ? <Icons.CheckCircle className="w-4 h-4 text-green-400" /> : <Icons.AlertTriangle className="w-4 h-4 text-yellow-400" />}<span className={canRemove.is_offline ? 'text-green-400' : 'text-yellow-400'}>{canRemove.is_offline ? 'Node Offline' : 'Node Online (recommended: shutdown after removal)'}</span></div>
                                {!canRemove.has_vms ? <div className="flex items-center gap-2"><Icons.CheckCircle className="w-4 h-4 text-green-400" /><span className="text-green-400">No VMs/CTs on node</span></div> : <div className="flex items-center gap-2"><Icons.XCircle className="w-4 h-4 text-red-400" /><span className="text-red-400">{canRemove.vm_count} VM(s)/CT(s) still on node</span></div>}
                            </div>)}
                            {canRemove && !canRemove.can_remove && canRemove.blockers?.length > 0 && (<div className="p-3 bg-red-500/20 border border-red-500/50 rounded-lg text-red-400 text-sm"><strong>Blockers:</strong><ul className="mt-1 ml-4 list-disc">{canRemove.blockers.map((b, i) => <li key={i}>{b}</li>)}</ul></div>)}
                            {canRemove?.warnings?.length > 0 && (<div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm flex items-start gap-2"><Icons.AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /><span>{canRemove.warnings.join('. ')}</span></div>)}
                            {canRemove?.can_remove && (<div><label className="block text-sm text-gray-400 mb-1">Type <strong className="text-white">{node.name}</strong> to confirm:</label><input type="text" value={confirmText} onChange={e => setConfirmText(e.target.value)} placeholder={node.name} className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white" /></div>)}
                        </div>
                        <div className="p-4 border-t border-proxmox-border flex justify-end gap-3">
                            <button onClick={onClose} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-border rounded-lg text-white">Cancel</button>
                            <button onClick={removeNode} disabled={loading || !canRemove?.can_remove || confirmText !== node.name} className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg disabled:opacity-50 flex items-center gap-2 text-white">{loading && <Icons.Loader className="w-4 h-4 animate-spin" />}Remove</button>
                        </div>
                    </div>
                </div>
            );
        }

        // NS: Feb 2026 - Move node between clusters: remove from source ↑ cleanup ↑ force join to target
        // MK: Always uses force:true for the join since node was just removed and has stale config
        function MoveNodeModal({ isOpen, onClose, nodeName, currentClusterId, clusters, onSuccess, addToast }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [loading, setLoading] = useState(false);
            const [error, setError] = useState(null);
            const [step, setStep] = useState(1); // 1=select target, 2=confirm, 3=progress
            const [targetCluster, setTargetCluster] = useState(null);
            const [password, setPassword] = useState('');
            const [progress, setProgress] = useState([]);
            
            const otherClusters = (clusters || []).filter(c => c.id !== currentClusterId);
            
            const startMove = async () => {
                if (!targetCluster || !password) return;
                setLoading(true); setError(null); setStep(3);
                setProgress([{ text: 'Removing node from current cluster...', status: 'running' }]);
                
                try {
                    // Remove from current cluster
                    const removeResp = await fetch(`${API_URL}/clusters/${currentClusterId}/nodes/${nodeName}/cluster-membership`, {
                        method: 'DELETE',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify({ confirm: true })
                    });
                    const removeData = await removeResp.json();
                    
                    if (!removeData.success) {
                        setProgress(prev => [...prev.slice(0, -1), { text: 'Remove from cluster failed', status: 'error' }]);
                        setError(removeData.error || 'Failed to remove node from current cluster');
                        setLoading(false);
                        return;
                    }
                    
                    const cleanupOk = removeData.cleanup?.success;
                    setProgress(prev => [
                        ...prev.slice(0, -1),
                        { text: 'Removed from current cluster' + (cleanupOk ? ' (config cleaned)' : ''), status: 'done' },
                        { text: `Getting join info from ${targetCluster.name}...`, status: 'running' }
                    ]);
                    
                    // Get join info from target cluster
                    const joinInfoResp = await fetch(`${API_URL}/clusters/${targetCluster.id}/datacenter/join-info`, {
                        credentials: 'include', headers: getAuthHeaders()
                    });
                    if (!joinInfoResp || !joinInfoResp.ok) {
                        setProgress(prev => [...prev.slice(0, -1), { text: 'Could not get join info', status: 'error' }]);
                        setError('Failed to get join info from target cluster. You may need to join manually.');
                        setLoading(false);
                        return;
                    }
                    
                    setProgress(prev => [
                        ...prev.slice(0, -1),
                        { text: `Got join info from ${targetCluster.name}`, status: 'done' },
                        { text: `Joining node to ${targetCluster.name}...`, status: 'running' }
                    ]);
                    
                    // Resolve node IP from current cluster knowledge
                    const nodeIp = await (async () => {
                        try {
                            const r = await fetch(`${API_URL}/clusters/${currentClusterId}/nodes`, {
                                credentials: 'include', headers: getAuthHeaders()
                            });
                            if (r && r.ok) {
                                const nodes = await r.json();
                                const n = (nodes.data || nodes || []).find(x => x.node === nodeName || x.name === nodeName);
                                return n?.ip || n?.ring0_addr || nodeName;
                            }
                        } catch {}
                        return nodeName;
                    })();
                    
                    // Join to target cluster
                    // NS: Feb 2026 - Always force since node was just removed and may have leftover config
                    const joinResp = await fetch(`${API_URL}/clusters/${targetCluster.id}/nodes/join`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify({ 
                            node_ip: nodeIp,
                            username: 'root',
                            password: password,
                            ssh_port: 22,
                            force: true
                        })
                    });
                    const joinData = await joinResp.json();
                    
                    if (joinData.success) {
                        setProgress(prev => [
                            ...prev.slice(0, -1),
                            { text: `Successfully joined ${targetCluster.name}!`, status: 'done' }
                        ]);
                        if (addToast) addToast(`Node ${nodeName} moved to ${targetCluster.name}`, 'success');
                        setTimeout(() => { if (onSuccess) onSuccess(); onClose(); }, 2000);
                    } else {
                        setProgress(prev => [
                            ...prev.slice(0, -1),
                            { text: 'Join failed - node removed but not joined', status: 'error' }
                        ]);
                        setError(`Node was removed from cluster but could not join target: ${joinData.error}. Join manually with pvecm.`);
                    }
                } catch (err) {
                    setError('Network error: ' + err.message);
                    setProgress(prev => [...prev.slice(0, -1), { text: 'Error', status: 'error' }]);
                } finally {
                    setLoading(false);
                }
            };
            
            if (!isOpen || !nodeName) return null;
            return (
                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
                    <div className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-md">
                        <div className="p-4 border-b border-proxmox-border">
                            <h2 className="text-lg font-semibold text-blue-400 flex items-center gap-2">
                                <Icons.ArrowRight className="w-5 h-5" />
                                {t('moveNodeToCluster') || 'Move Node to another Cluster'}
                            </h2>
                        </div>
                        <div className="p-4 space-y-4">
                            {error && <div className="p-3 bg-red-500/20 border border-red-500 rounded-lg text-red-400 text-sm">{error}</div>}
                            
                            {step === 1 && (<>
                                <p className="text-gray-300 text-sm">
                                    Move <strong className="text-white">{nodeName}</strong> to another cluster. 
                                    This will remove it from the current cluster and join it to the target.
                                </p>
                                
                                <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 text-yellow-400 text-sm flex items-start gap-2">
                                    <Icons.AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                                    <span>All VMs must be migrated off this node first. The node must be in maintenance mode.</span>
                                </div>
                                
                                {otherClusters.length === 0 ? (
                                    <p className="text-gray-500 text-sm italic">No other clusters available.</p>
                                ) : (
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-2">{t('targetCluster') || 'Target Cluster'}</label>
                                        <div className="space-y-2">
                                            {otherClusters.map(c => (
                                                <button
                                                    key={c.id}
                                                    onClick={() => setTargetCluster(c)}
                                                    className={`w-full text-left px-3 py-2.5 rounded-lg border transition-colors flex items-center justify-between ${
                                                        targetCluster?.id === c.id 
                                                            ? 'border-blue-500 bg-blue-500/10 text-white' 
                                                            : 'border-proxmox-border bg-proxmox-dark text-gray-300 hover:border-gray-500'
                                                    }`}
                                                >
                                                    <span className="flex items-center gap-2">
                                                        <Icons.Server className="w-4 h-4" />
                                                        {c.name}
                                                    </span>
                                                    {targetCluster?.id === c.id && <Icons.CheckCircle className="w-4 h-4 text-blue-400" />}
                                                </button>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                
                                {targetCluster && (
                                    <div>
                                        <label className="block text-sm text-gray-400 mb-1">Root password of {nodeName}</label>
                                        <input 
                                            type="password" 
                                            value={password} 
                                            onChange={e => setPassword(e.target.value)} 
                                            placeholder="Node root password for SSH" 
                                            className="w-full bg-proxmox-dark border border-proxmox-border rounded px-3 py-2 text-white" 
                                        />
                                        <p className="text-xs text-gray-500 mt-1">Needed to SSH into the node and run pvecm join</p>
                                    </div>
                                )}
                            </>)}
                            
                            {step === 3 && (
                                <div className="space-y-2">
                                    {progress.map((p, i) => (
                                        <div key={i} className="flex items-center gap-2 text-sm">
                                            {p.status === 'running' && <Icons.Loader className="w-4 h-4 text-blue-400 animate-spin" />}
                                            {p.status === 'done' && <Icons.CheckCircle className="w-4 h-4 text-green-400" />}
                                            {p.status === 'error' && <Icons.XCircle className="w-4 h-4 text-red-400" />}
                                            <span className={p.status === 'error' ? 'text-red-400' : p.status === 'done' ? 'text-green-400' : 'text-gray-300'}>{p.text}</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                        <div className="p-4 border-t border-proxmox-border flex justify-end gap-3">
                            <button onClick={onClose} disabled={loading} className="px-4 py-2 bg-proxmox-dark hover:bg-proxmox-border rounded-lg text-white disabled:opacity-50">
                                {step === 3 && !loading ? 'Close' : 'Cancel'}
                            </button>
                            {step === 1 && (
                                <button 
                                    onClick={startMove} 
                                    disabled={!targetCluster || !password || loading} 
                                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50 flex items-center gap-2 text-white"
                                >
                                    {loading && <Icons.Loader className="w-4 h-4 animate-spin" />}
                                    Move Node
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            );
        }

