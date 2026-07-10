        // ═══════════════════════════════════════════════
        // PegaProx - UI Components
        // Charts, Gauge, Toast, NodeJoin wizards
        // ═══════════════════════════════════════════════

        // LW May 2026 — picks the layout-appropriate logo at render time.
        // dark pegasus only when corporate light is active; everywhere else the white pegasus
        // looks correct against the dark backgrounds. reads body data-attr so it updates
        // synchronously with the corp-theme toggle.
        function getLogoSrc() {
            try {
                return document.body?.dataset?.corpTheme === 'light'
                    ? '/images/pegaprox-logo-light.png'
                    : '/images/pegaprox-logo-dark.png';
            } catch (_) {
                return '/images/pegaprox-logo-dark.png';
            }
        }

        // MK: Apr 2026 - PDF generator with professional template
        // uses jsPDF + autoTable, loaded via CDN with local fallback
        // NS May 2026 — switched PDF logo to the light variant (dark pegasus on transparent)
        // because the PDF template is white-paper-on-print
        let _pdfLogoCache = null;

        async function _loadPdfLogo() {
            if (_pdfLogoCache) return _pdfLogoCache;
            try {
                const resp = await fetch('/images/pegaprox-logo-light.png');
                const blob = await resp.blob();
                return new Promise((resolve) => {
                    const reader = new FileReader();
                    reader.onloadend = () => { _pdfLogoCache = reader.result; resolve(reader.result); };
                    reader.readAsDataURL(blob);
                });
            } catch(e) { return null; }
        }

        // NS: main entry point for all PegaProx PDF exports
        async function generatePegaProxPDF({ title, subtitle, clusterName, content, filename, orientation }) {
            if (typeof window.jspdf === 'undefined') {
                console.error('[PDF] jsPDF not loaded');
                return;
            }
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF({ orientation: orientation || 'portrait', unit: 'mm', format: 'a4' });
            const pageW = doc.internal.pageSize.getWidth();
            const pageH = doc.internal.pageSize.getHeight();
            const margin = 15;
            const contentW = pageW - margin * 2;
            const logoData = await _loadPdfLogo();
            let y = margin;

            // ── Header ──
            const headerH = 28;
            doc.setFillColor(26, 32, 39); // #1a2027
            doc.rect(0, 0, pageW, headerH, 'F');
            // orange accent bar
            doc.setFillColor(229, 112, 0); // #E57000
            doc.rect(0, headerH, pageW, 1.2, 'F');

            if (logoData) {
                try { doc.addImage(logoData, 'PNG', margin, 4, 20, 20); } catch(e) {}
            }
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(16);
            doc.setTextColor(233, 236, 239); // #e9ecef
            doc.text(title || 'PegaProx Report', margin + 24, 12);
            doc.setFontSize(9);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(150, 160, 170);
            const sub = [subtitle, clusterName, new Date().toLocaleString()].filter(Boolean).join('  |  ');
            doc.text(sub, margin + 24, 18);
            if (PEGAPROX_VERSION) {
                doc.setFontSize(7);
                doc.setTextColor(100, 110, 120);
                doc.text(`v${PEGAPROX_VERSION}`, pageW - margin - 2, 24, { align: 'right' });
            }

            y = headerH + 6;

            // ── Content Blocks ──
            const addPageIfNeeded = (neededH) => {
                if (y + neededH > pageH - 18) {
                    doc.addPage();
                    y = margin;
                    return true;
                }
                return false;
            };

            for (const block of (content || [])) {
                if (block.type === 'stats') {
                    addPageIfNeeded(30);
                    const stats = block.data || [];
                    const boxW = Math.min(38, (contentW - (stats.length - 1) * 4) / stats.length);
                    const totalW = stats.length * boxW + (stats.length - 1) * 4;
                    let sx = margin + (contentW - totalW) / 2;
                    stats.forEach(s => {
                        // box bg
                        doc.setFillColor(240, 242, 245);
                        doc.roundedRect(sx, y, boxW, 22, 2, 2, 'F');
                        // value
                        doc.setFont('helvetica', 'bold');
                        doc.setFontSize(18);
                        const rgb = _hexToRgb(s.color || '#333');
                        doc.setTextColor(rgb.r, rgb.g, rgb.b);
                        doc.text(String(s.value), sx + boxW / 2, y + 11, { align: 'center' });
                        // label
                        doc.setFont('helvetica', 'normal');
                        doc.setFontSize(8);
                        doc.setTextColor(100, 100, 100);
                        doc.text(s.label, sx + boxW / 2, y + 18, { align: 'center' });
                        sx += boxW + 4;
                    });
                    y += 28;
                }

                else if (block.type === 'table') {
                    addPageIfNeeded(20);
                    if (block.title) {
                        doc.setFont('helvetica', 'bold');
                        doc.setFontSize(11);
                        doc.setTextColor(50, 50, 50);
                        doc.text(block.title, margin, y + 4);
                        y += 8;
                    }
                    doc.autoTable({
                        startY: y,
                        margin: { left: margin, right: margin },
                        head: [block.columns],
                        body: block.rows,
                        theme: 'grid',
                        styles: { fontSize: 8, cellPadding: 2.5, lineColor: [220,220,220], lineWidth: 0.2 },
                        headStyles: { fillColor: [229, 112, 0], textColor: 255, fontStyle: 'bold', fontSize: 8.5 },
                        alternateRowStyles: { fillColor: [248, 249, 250] },
                        // severity color coding for CVE reports
                        didParseCell: function(data) {
                            if (data.section === 'body') {
                                const val = String(data.cell.raw || '').toLowerCase();
                                if (val === 'high' || val === 'critical') {
                                    data.cell.styles.textColor = [220, 50, 50];
                                    data.cell.styles.fontStyle = 'bold';
                                } else if (val === 'medium') {
                                    data.cell.styles.textColor = [200, 150, 0];
                                } else if (val === 'low') {
                                    data.cell.styles.textColor = [60, 130, 200];
                                }
                            }
                        }
                    });
                    y = doc.lastAutoTable.finalY + 6;
                }

                else if (block.type === 'text') {
                    addPageIfNeeded(10);
                    doc.setFont('helvetica', 'normal');
                    doc.setFontSize(9);
                    doc.setTextColor(60, 60, 60);
                    const lines = doc.splitTextToSize(block.value, contentW);
                    doc.text(lines, margin, y + 4);
                    y += lines.length * 4 + 4;
                }

                else if (block.type === 'image') {
                    const imgW = Math.min(block.width || contentW, contentW);
                    const ratio = (block.height || 100) / (block.width || contentW);
                    const imgH = imgW * ratio;
                    addPageIfNeeded(imgH + 4);
                    try { doc.addImage(block.dataUrl, 'JPEG', margin, y, imgW, imgH); } catch(e) {}
                    y += imgH + 4;
                }

                else if (block.type === 'spacer') {
                    y += block.height || 8;
                }
            }

            // ── Footers on all pages ──
            const totalPages = doc.internal.getNumberOfPages();
            for (let i = 1; i <= totalPages; i++) {
                doc.setPage(i);
                doc.setFillColor(245, 245, 245);
                doc.rect(0, pageH - 10, pageW, 10, 'F');
                doc.setDrawColor(220, 220, 220);
                doc.line(0, pageH - 10, pageW, pageH - 10);
                doc.setFont('helvetica', 'normal');
                doc.setFontSize(7);
                doc.setTextColor(140, 140, 140);
                doc.text(`PegaProx ${PEGAPROX_VERSION ? 'v' + PEGAPROX_VERSION : ''}`, margin, pageH - 4);
                doc.text('Confidential', pageW / 2, pageH - 4, { align: 'center' });
                doc.text(`Page ${i} / ${totalPages}`, pageW - margin, pageH - 4, { align: 'right' });
            }

            doc.save(filename || 'pegaprox-report.pdf');
        }

        function _hexToRgb(hex) {
            const r = parseInt(hex.slice(1,3), 16) || 0;
            const g = parseInt(hex.slice(3,5), 16) || 0;
            const b = parseInt(hex.slice(5,7), 16) || 0;
            return {r, g, b};
        }

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

        function getUserInitials(user) {
            const displayName = user?.display_name || user?.username || '';
            const parts = displayName.trim().split(/\s+/).filter(Boolean);
            if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
            return (displayName[0] || 'U').toUpperCase();
        }

        function UserAvatar({ user, sizeClass = 'w-8 h-8', textClass = 'text-sm', className = '' }) {
            const initials = getUserInitials(user);
            const classes = `${sizeClass} rounded-full overflow-hidden flex items-center justify-center ${className}`.trim();

            if (user?.avatar_url) {
                return (
                    <img
                        src={user.avatar_url}
                        alt={`${user?.display_name || user?.username || 'User'} avatar`}
                        className={`${classes} object-cover border border-proxmox-border/60`}
                    />
                );
            }

            return (
                <div className={`${classes} bg-proxmox-orange/20 text-proxmox-orange font-semibold ${textClass}`}>
                    {initials}
                </div>
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
                    // #231: auto-detect span to choose label format
                    const span = timestamps[timestamps.length - 1] - timestamps[0];
                    const useDateOnly = span > 86400 * 14;  // > 2 weeks
                    const useDate = span > 86400 * 2;        // > 2 days
                    for (let i = 0; i < timestamps.length; i++) {
                        const d = new Date(timestamps[i] * 1000);
                        if (useDateOnly) {
                            rawLabels.push(d.toLocaleDateString([], { month: 'short', day: 'numeric' }));
                        } else if (useDate) {
                            rawLabels.push(d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
                        } else {
                            rawLabels.push(d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
                        }
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
                                    // NS: adapt tooltip to corp light mode
                                    backgroundColor: document.body.dataset.corpTheme === 'light' ? 'rgba(255,255,255,0.95)' : 'rgba(30, 30, 40, 0.95)',
                                    titleColor: document.body.dataset.corpTheme === 'light' ? '#333' : '#e5e7eb',
                                    bodyColor: document.body.dataset.corpTheme === 'light' ? '#555' : '#fff',
                                    borderColor: document.body.dataset.corpTheme === 'light' ? '#cfd8dc' : 'rgba(255,255,255,0.1)',
                                    borderWidth: document.body.dataset.corpTheme === 'light' ? 1 : 0,
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
                                        color: document.body.dataset.corpTheme === 'light' ? '#888' : '#6b7280',
                                        font: { size: 10 },
                                        maxTicksLimit: 8,
                                        maxRotation: 0,
                                    },
                                    grid: { color: document.body.dataset.corpTheme === 'light' ? 'rgba(0,0,0,0.08)' : 'rgba(75, 85, 99, 0.3)' }
                                },
                                y: {
                                    beginAtZero: true,
                                    min: yMin,
                                    max: yMax,
                                    ticks: {
                                        color: document.body.dataset.corpTheme === 'light' ? '#888' : '#6b7280',
                                        font: { size: 10 },
                                        callback: function(value) {
                                            var fn = formatRef.current;
                                            if (fn) return fn(value) + (unitStr.trim() ? unitStr : '');
                                            return value.toFixed(yMax && yMax <= 10 ? 1 : 0) + unitStr;
                                        }
                                    },
                                    grid: { color: document.body.dataset.corpTheme === 'light' ? 'rgba(0,0,0,0.08)' : 'rgba(75, 85, 99, 0.3)' }
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
            
            // Sponsor URLs - edit these to add sponsor links
            const sponsorLinks = {
                1: 'https://socialfurr.com',
                2: 'https://www.netwolk.ch',
                3: 'https://expertize.nl/',  // Banner Oranje - Platinum
                4: 'https://netzware.at/',  // Netzware - Platinum
                5: 'https://www.occentus.net/',  // Occentus Network - Platinum

                6: null,
                7: null,
                8: null
            };
            
            const handleImageError = () => {
                setHasImage(false);
            };
            
            const url = sponsorLinks[num];
            const isEmptySlot = url === null;
            const imageSrc = `/images/sponsors/sponsor${num}.png`;

            if (!hasImage || isEmptySlot) {
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

        // NS: Mar 2026 - context menu for corporate sidebar (right-click actions)
        function ContextMenu({ items, position, onClose }) {
            const menuRef = React.useRef(null);
            const [adjusted, setAdjusted] = React.useState(position);
            const [hoveredSub, setHoveredSub] = React.useState(null);
            const [focusIdx, setFocusIdx] = React.useState(-1);

            // boundary check - flip if menu would go off screen
            React.useLayoutEffect(() => {
                if (!menuRef.current) return;
                const rect = menuRef.current.getBoundingClientRect();
                let x = position.x, y = position.y;
                if (x + rect.width > window.innerWidth - 8) x = position.x - rect.width;
                if (y + rect.height > window.innerHeight - 8) y = Math.max(8, window.innerHeight - rect.height - 8);
                if (x !== position.x || y !== position.y) setAdjusted({ x, y });
            }, [position]);

            // NS: auto-focus menu on mount so keyboard nav works immediately
            React.useEffect(() => { menuRef.current?.focus(); }, []);

            // esc to close
            React.useEffect(() => {
                const onKey = (e) => {
                    if (e.key === 'Escape') { e.stopPropagation(); onClose(); }
                };
                document.addEventListener('keydown', onKey, true);
                return () => document.removeEventListener('keydown', onKey, true);
            }, [onClose]);

            // keyboard nav
            const actionableItems = items.map((item, i) => ({ ...item, _idx: i })).filter(it => !it.separator);
            const handleKeyDown = (e) => {
                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    setFocusIdx(prev => {
                        const next = prev + 1;
                        return next >= actionableItems.length ? 0 : next;
                    });
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    setFocusIdx(prev => {
                        const next = prev - 1;
                        return next < 0 ? actionableItems.length - 1 : next;
                    });
                } else if (e.key === 'Enter' && focusIdx >= 0 && focusIdx < actionableItems.length) {
                    const item = actionableItems[focusIdx];
                    if (item.onClick && !item.disabled && !item.submenu) {
                        item.onClick();
                        onClose();
                    }
                }
            };

            const renderSubmenu = (submenu, parentRect) => {
                // MK: position submenu to the right, flip if no space
                let sx = parentRect.right + 2;
                let sy = parentRect.top;
                if (sx + 200 > window.innerWidth) sx = parentRect.left - 202;
                if (sy + submenu.length * 30 > window.innerHeight) sy = Math.max(8, window.innerHeight - submenu.length * 30 - 8);

                return (
                    <div className="corp-context-menu fixed rounded z-[1000]" style={{ left: sx, top: sy }} onClick={(e) => e.stopPropagation()}>
                        {submenu.map((sub, si) => sub.separator ? (
                            <div key={`sep-${si}`} className="corp-ctx-separator" />
                        ) : (
                            <button
                                key={sub.label}
                                className={`corp-ctx-item${sub.danger ? ' ctx-danger' : ''}`}
                                disabled={sub.disabled}
                                onClick={() => { if (sub.onClick) sub.onClick(); onClose(); }}
                            >
                                {sub.icon && <span className="w-4 h-4 flex items-center justify-center flex-shrink-0">{sub.icon}</span>}
                                <span>{sub.label}</span>
                            </button>
                        ))}
                    </div>
                );
            };

            return (
                <>
                    {/* backdrop */}
                    <div className="fixed inset-0 z-[998]" onClick={onClose} onContextMenu={(e) => { e.preventDefault(); onClose(); }} />
                    {/* menu */}
                    <div
                        ref={menuRef}
                        className="corp-context-menu fixed rounded z-[999]"
                        style={{ left: adjusted.x, top: adjusted.y }}
                        tabIndex={-1}
                        onKeyDown={handleKeyDown}
                    >
                        {items.map((item, idx) => {
                            if (item.separator) return <div key={`sep-${idx}`} className="corp-ctx-separator" />;

                            const isFocused = actionableItems[focusIdx]?._idx === idx;
                            const hasSubmenu = item.submenu && item.submenu.length > 0;

                            return (
                                <div key={item.label || idx} className="relative"
                                    onMouseEnter={(e) => { if (hasSubmenu) setHoveredSub({ idx, rect: e.currentTarget.getBoundingClientRect() }); else setHoveredSub(null); }}
                                >
                                    <button
                                        className={`corp-ctx-item${item.danger ? ' ctx-danger' : ''}${isFocused ? ' bg-[#29414e] !text-[#e9ecef]' : ''}`}
                                        disabled={item.disabled}
                                        onClick={() => {
                                            if (hasSubmenu) return;
                                            if (item.onClick) item.onClick();
                                            onClose();
                                        }}
                                    >
                                        {item.icon && <span className="w-4 h-4 flex items-center justify-center flex-shrink-0">{item.icon}</span>}
                                        <span className="flex-1">{item.label}</span>
                                        {hasSubmenu && <Icons.ChevronRight className="w-3 h-3 corp-ctx-submenu-arrow" />}
                                    </button>
                                    {hasSubmenu && hoveredSub?.idx === idx && renderSubmenu(item.submenu, hoveredSub.rect)}
                                </div>
                            );
                        })}
                    </div>
                </>
            );
        }

        // LW May 2026 — small one-click copy. Pure UI, no deps.
        // Used wherever the user might want to grab an ID, IP, hostname, ticket.
        function CopyButton({ value, label, className, size = 'sm', title }) {
            const [done, setDone] = React.useState(false);
            if (!value && value !== 0) return null;
            const sizes = size === 'xs' ? 'w-3 h-3' : size === 'md' ? 'w-4 h-4' : 'w-3.5 h-3.5';
            const onClick = async (e) => {
                e.stopPropagation();
                e.preventDefault();
                try {
                    if (navigator.clipboard && window.isSecureContext) {
                        await navigator.clipboard.writeText(String(value));
                    } else {
                        // fallback: hidden textarea — works under http on LAN
                        const ta = document.createElement('textarea');
                        ta.value = String(value);
                        ta.style.position = 'fixed';
                        ta.style.opacity = '0';
                        document.body.appendChild(ta);
                        ta.select();
                        try { document.execCommand('copy'); } finally { document.body.removeChild(ta); }
                    }
                    setDone(true);
                    setTimeout(() => setDone(false), 1100);
                } catch (_) {
                    /* noop */
                }
            };
            return (
                <button
                    type="button"
                    onClick={onClick}
                    title={title || (label ? 'Copy ' + label : 'Copy')}
                    className={`inline-flex items-center justify-center text-gray-400 hover:text-proxmox-orange transition-colors ${className || ''}`}
                    style={{ background: 'transparent', padding: '2px', borderRadius: '3px', verticalAlign: 'middle' }}
                >
                    {done
                        ? <Icons.Check className={sizes} style={{ color: '#10b981' }} />
                        : <Icons.Copy className={sizes} />}
                </button>
            );
        }
        // expose on window for non-React call sites (e.g. inline handlers in tables)
        try { window.PegaProxCopyButton = CopyButton; } catch (_) {}

        // MK May 2026 — keyboard shortcuts overlay. Toggled with `?`.
        // Centralised list lives here so we don't grow stale documentation.
        const KEYBOARD_SHORTCUTS = [
            { keys: ['Ctrl', 'K'], altKeys: ['⌘', 'K'], desc: 'Quick search / command palette' },
            { keys: ['?'],                              desc: 'Toggle this help' },
            { keys: ['Esc'],                            desc: 'Close modal / dropdown' },
            { keys: ['/'],                              desc: 'Focus search input on current view' },
            { keys: ['g', 'd'],                         desc: 'Go to Overview' },
            { keys: ['g', 'r'],                         desc: 'Go to Resources' },
            { keys: ['g', 's'],                         desc: 'Go to Datacenter' },
            { keys: ['g', 'a'],                         desc: 'Go to Automation' },
            { keys: ['g', 'p'],                         desc: 'Go to Reports' },
            { keys: ['g', ','],                         desc: 'Open Settings' },
            { keys: ['n'],                              desc: 'New VM (current cluster)' },
            { keys: ['Shift', 'N'],                     desc: 'New container (current cluster)' },
            { keys: ['r'],                              desc: 'Refresh active cluster' },
            { keys: ['t'],                              desc: 'Toggle theme (light/dark)' },
            { keys: ['Shift', '?'],                     desc: 'Show keyboard shortcuts' },
        ];

        function KeyboardShortcutsModal({ open, onClose }) {
            React.useEffect(() => {
                if (!open) return;
                const onKey = (e) => { if (e.key === 'Escape') { e.preventDefault(); onClose(); } };
                window.addEventListener('keydown', onKey);
                return () => window.removeEventListener('keydown', onKey);
            }, [open, onClose]);
            if (!open) return null;
            const isMac = (typeof navigator !== 'undefined' && /mac/i.test(navigator.platform || ''));
            return (
                <div className="fixed inset-0 z-[10010] flex items-center justify-center p-4" style={{ background: 'rgba(8, 14, 24, 0.72)' }} onClick={onClose}>
                    <div
                        className="rounded-lg shadow-2xl w-full max-w-2xl"
                        style={{ background: 'var(--corp-surface, #1c2733)', color: 'var(--corp-text, #e9ecef)', border: '1px solid var(--corp-border, #29414e)' }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="px-5 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--corp-border, #29414e)' }}>
                            <div className="flex items-center gap-2">
                                <Icons.Keyboard className="w-5 h-5" style={{ color: 'var(--corp-accent, #0078a8)' }} />
                                <h3 className="text-base font-semibold">Keyboard Shortcuts</h3>
                            </div>
                            <button onClick={onClose} className="opacity-60 hover:opacity-100 text-lg leading-none" aria-label="close">×</button>
                        </div>
                        <div className="p-5 grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 text-sm">
                            {KEYBOARD_SHORTCUTS.map((sc, i) => {
                                const keys = isMac && sc.altKeys ? sc.altKeys : sc.keys;
                                return (
                                    <div key={i} className="flex items-center justify-between gap-3 py-1.5">
                                        <span className="opacity-85">{sc.desc}</span>
                                        <span className="flex items-center gap-1 flex-shrink-0">
                                            {keys.map((k, idx) => (
                                                <React.Fragment key={idx}>
                                                    <kbd
                                                        className="px-1.5 py-0.5 text-xs font-mono rounded"
                                                        style={{
                                                            background: 'var(--corp-surface-2, #29414e)',
                                                            border: '1px solid var(--corp-border, #485764)',
                                                            color: 'var(--corp-text, #e9ecef)',
                                                            minWidth: '20px',
                                                            textAlign: 'center',
                                                        }}
                                                    >{k}</kbd>
                                                    {idx < keys.length - 1 && <span className="opacity-50 text-xs">then</span>}
                                                </React.Fragment>
                                            ))}
                                        </span>
                                    </div>
                                );
                            })}
                        </div>
                        <div className="px-5 py-3 text-xs opacity-60" style={{ borderTop: '1px solid var(--corp-border, #29414e)' }}>
                            Press <kbd className="px-1 rounded" style={{ background: 'var(--corp-surface-2, #29414e)', border: '1px solid var(--corp-border, #485764)' }}>Esc</kbd> to close
                        </div>
                    </div>
                </div>
            );
        }

        // NS — sticky banner at top while WS is dropped. Auto-shows after 4s of disconnect
        // so a quick reconnect-blip doesn't flash a scary banner. Passive: gets state via prop.
        function ConnectionLostBanner({ connected, reconnectingMs }) {
            const [visible, setVisible] = React.useState(false);
            React.useEffect(() => {
                let tid;
                if (connected) {
                    setVisible(false);
                } else {
                    tid = setTimeout(() => setVisible(true), 4000);
                }
                return () => { if (tid) clearTimeout(tid); };
            }, [connected]);
            if (!visible) return null;
            return (
                <div
                    className="w-full text-sm px-4 py-2 flex items-center justify-center gap-3"
                    style={{
                        position: 'sticky', top: 0, zIndex: 100,
                        background: 'linear-gradient(180deg, #b94a3a 0%, #9c3e2f 100%)',
                        color: '#fff',
                        boxShadow: '0 2px 4px rgba(0,0,0,0.2)',
                    }}
                >
                    <span className="inline-flex w-2 h-2 rounded-full" style={{ background: '#fde68a', boxShadow: '0 0 6px #fde68a', animation: 'pulse 1.4s infinite' }} />
                    <span className="font-medium">Live updates disconnected</span>
                    <span className="opacity-80">Trying to reconnect{reconnectingMs ? ` (${Math.round(reconnectingMs/1000)}s)` : '…'}</span>
                </div>
            );
        }

        // LW — CSV utility. Uses RFC4180 quoting. Hand it an array of objects + columns.
        // columns can be ['vmid','name'] or [{key:'vmid', label:'VMID', map:row=>row.vmid}].
        function downloadCsv(filename, rows, columns) {
            if (!Array.isArray(rows)) rows = [];
            const cols = (columns && columns.length) ? columns : (rows[0] ? Object.keys(rows[0]).map(k => ({key: k, label: k})) : []);
            const escape = (v) => {
                if (v === null || v === undefined) return '';
                let s = String(v);
                // NS: CWE-1236 — neutralise CSV formula injection. A cell starting with
                // = + - @ (or tab/CR) is run as a formula by Excel/Sheets; prefix with a
                // single quote so spreadsheets render it as plain text.
                if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
                return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
            };
            const head = cols.map(c => escape(c.label || c.key)).join(',');
            const body = rows.map(r => cols.map(c => {
                const val = c.map ? c.map(r) : r[c.key];
                return escape(val);
            }).join(',')).join('\r\n');
            // BOM so Excel opens UTF-8 correctly
            const blob = new Blob(['﻿', head, '\r\n', body], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename || 'export.csv';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 200);
        }
        function downloadJson(filename, payload) {
            const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename || 'export.json';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 200);
        }
        try {
            window.PegaProxDownloadCsv = downloadCsv;
            window.PegaProxDownloadJson = downloadJson;
        } catch (_) {}

        // NS — opt-in pre-action snapshot pref. Stored in localStorage so it survives reload.
        // Read by destructive flows (delete VM, restore, change boot, migrate to other cluster).
        const AUTO_SNAPSHOT_KEY = 'pegaprox-auto-snapshot-before-destructive';
        function getAutoSnapshotPref() {
            try { return localStorage.getItem(AUTO_SNAPSHOT_KEY) === '1'; } catch (_) { return false; }
        }
        function setAutoSnapshotPref(v) {
            try { localStorage.setItem(AUTO_SNAPSHOT_KEY, v ? '1' : '0'); } catch (_) {}
        }
        try {
            window.PegaProxAutoSnap = { get: getAutoSnapshotPref, set: setAutoSnapshotPref };
        } catch (_) {}

        // MK — quick filter chip row. Drop above any list. Fully controlled.
        // chips: [{ id, label, count }, ...]; selected: array of chip ids; onChange(newSelection)
        function FilterChips({ chips, selected, onChange, multiSelect = true, className = '' }) {
            const sel = new Set(selected || []);
            const toggle = (id) => {
                let next;
                if (multiSelect) {
                    next = new Set(sel);
                    next.has(id) ? next.delete(id) : next.add(id);
                } else {
                    next = sel.has(id) && sel.size === 1 ? new Set() : new Set([id]);
                }
                onChange(Array.from(next));
            };
            return (
                <div className={`flex flex-wrap items-center gap-1.5 ${className}`}>
                    {chips.map(c => {
                        const active = sel.has(c.id);
                        return (
                            <button
                                key={c.id}
                                type="button"
                                onClick={() => toggle(c.id)}
                                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-full transition-all"
                                style={{
                                    background: active ? 'var(--corp-accent, #0078a8)' : 'var(--corp-surface-2, #29414e)',
                                    color: active ? '#fff' : 'var(--corp-text, #e9ecef)',
                                    border: '1px solid ' + (active ? 'var(--corp-accent, #0078a8)' : 'var(--corp-border, #485764)'),
                                    fontWeight: active ? 600 : 500,
                                }}
                            >
                                {c.icon && <span className="opacity-80">{c.icon}</span>}
                                <span>{c.label}</span>
                                {typeof c.count === 'number' && (
                                    <span className="opacity-70 ml-0.5">{c.count}</span>
                                )}
                            </button>
                        );
                    })}
                    {(sel.size > 0) && (
                        <button
                            type="button"
                            onClick={() => onChange([])}
                            className="text-xs opacity-60 hover:opacity-100 ml-1"
                            style={{ background: 'transparent', color: 'var(--corp-text, #e9ecef)' }}
                        >Clear</button>
                    )}
                </div>
            );
        }

        // LW May 2026 — at-a-glance number tile. Used on the overview header.
        function StatTile({ label, value, sub, color, icon: IconC, onClick }) {
            const clickable = !!onClick;
            return (
                <div
                    className={`rounded-md p-3 ${clickable ? 'cursor-pointer' : ''}`}
                    style={{
                        background: 'var(--corp-surface, #1c2733)',
                        border: '1px solid var(--corp-border, #29414e)',
                        minWidth: '140px',
                        transition: 'border-color .15s',
                    }}
                    onClick={onClick}
                    onMouseEnter={(e) => clickable && (e.currentTarget.style.borderColor = color || 'var(--corp-accent, #0078a8)')}
                    onMouseLeave={(e) => clickable && (e.currentTarget.style.borderColor = 'var(--corp-border, #29414e)')}
                >
                    <div className="flex items-center justify-between">
                        <span className="text-xs uppercase tracking-wide opacity-70">{label}</span>
                        {IconC && <IconC className="w-3.5 h-3.5 opacity-60" style={{ color: color || 'var(--corp-accent, #0078a8)' }} />}
                    </div>
                    <div className="mt-1 text-2xl font-semibold" style={{ color: color || 'var(--corp-text, #e9ecef)' }}>{value}</div>
                    {sub && <div className="text-xs opacity-60 mt-0.5">{sub}</div>}
                </div>
            );
        }
        try { window.PegaProxStatTile = StatTile; } catch (_) {}

        // NS May 2026 — single-number cluster health pill. Polls /health every 60s.
        // Hover for factor breakdown, click for full modal.
        function ClusterHealthBadge({ clusterId, authFetch, apiUrl }) {
            const [data, setData] = React.useState(null);
            const [loading, setLoading] = React.useState(false);
            const [showDetails, setShowDetails] = React.useState(false);
            const [hovering, setHovering] = React.useState(false);

            const fetchHealth = React.useCallback(async () => {
                if (!clusterId || !authFetch) return;
                setLoading(true);
                try {
                    const res = await authFetch(`${apiUrl}/clusters/${clusterId}/health`);
                    if (res && res.ok) {
                        setData(await res.json());
                    } else if (res && res.status === 503) {
                        setData({ score: 0, band: 'critical', factors: [], issues: ['Offline'] });
                    }
                } catch (_) { /* keep last */ }
                finally { setLoading(false); }
            }, [clusterId, authFetch, apiUrl]);

            React.useEffect(() => {
                fetchHealth();
                const id = setInterval(fetchHealth, 60000);
                return () => clearInterval(id);
            }, [fetchHealth]);

            if (!clusterId) return null;
            if (!data && loading) {
                return <span className="corp-badge" style={{ background: 'rgba(150,150,150,0.15)', color: '#999', border: '1px solid rgba(150,150,150,0.3)' }}>… score</span>;
            }
            if (!data) return null;

            const colors = {
                excellent: { bg: 'rgba(96,181,21,0.18)', fg: '#60b515', bd: 'rgba(96,181,21,0.4)' },
                good:      { bg: 'rgba(151,189,52,0.18)', fg: '#97bd34', bd: 'rgba(151,189,52,0.4)' },
                warning:   { bg: 'rgba(247,180,40,0.18)', fg: '#f7b428', bd: 'rgba(247,180,40,0.4)' },
                degraded:  { bg: 'rgba(238,142,38,0.18)', fg: '#ee8e26', bd: 'rgba(238,142,38,0.4)' },
                critical:  { bg: 'rgba(245,79,71,0.18)', fg: '#f54f47', bd: 'rgba(245,79,71,0.4)' },
            };
            const c = colors[data.band] || colors.warning;

            return (
                <>
                    <span
                        className="corp-badge"
                        style={{
                            background: c.bg, color: c.fg, border: `1px solid ${c.bd}`,
                            cursor: 'pointer', position: 'relative', userSelect: 'none',
                            display: 'inline-flex', alignItems: 'center', gap: '4px',
                        }}
                        onClick={() => setShowDetails(true)}
                        onMouseEnter={() => setHovering(true)}
                        onMouseLeave={() => setHovering(false)}
                        title="Cluster health — click for breakdown"
                    >
                        <span style={{ fontWeight: 700, letterSpacing: '0.02em' }}>{data.score}</span>
                        <span style={{ opacity: 0.75, fontSize: '0.7rem' }}>health</span>
                        {hovering && Array.isArray(data.factors) && data.factors.length > 0 && (
                            <div style={{
                                position: 'absolute', top: '100%', right: 0, marginTop: '4px',
                                background: 'var(--corp-surface, #1c2733)',
                                border: '1px solid var(--corp-border, #29414e)',
                                borderRadius: '4px', padding: '8px 10px',
                                color: 'var(--corp-text, #e9ecef)',
                                fontSize: '0.72rem', minWidth: '220px', zIndex: 200,
                                boxShadow: '0 4px 12px rgba(0,0,0,0.3)', textAlign: 'left',
                                whiteSpace: 'nowrap',
                            }}>
                                {data.factors.map((f, i) => (
                                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', padding: '2px 0' }}>
                                        <span style={{ opacity: 0.8 }}>{f.label}</span>
                                        <span style={{
                                            color: f.delta < 0 ? '#f54f47' : '#60b515',
                                            fontVariantNumeric: 'tabular-nums',
                                        }}>{f.delta < 0 ? f.delta : 'ok'}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </span>
                    {showDetails && (
                        <ClusterHealthModal data={data} onClose={() => setShowDetails(false)} />
                    )}
                </>
            );
        }

        function ClusterHealthModal({ data, onClose }) {
            React.useEffect(() => {
                const onKey = (e) => { if (e.key === 'Escape') onClose(); };
                window.addEventListener('keydown', onKey);
                return () => window.removeEventListener('keydown', onKey);
            }, [onClose]);
            const colors = {
                excellent: '#60b515', good: '#97bd34', warning: '#f7b428',
                degraded: '#ee8e26', critical: '#f54f47',
            };
            const fg = colors[data.band] || '#999';
            return (
                <div className="fixed inset-0 z-[10010] flex items-center justify-center p-4" style={{ background: 'rgba(8,14,24,0.72)' }} onClick={onClose}>
                    <div
                        className="rounded-lg shadow-2xl w-full max-w-xl"
                        style={{ background: 'var(--corp-surface, #1c2733)', color: 'var(--corp-text, #e9ecef)', border: '1px solid var(--corp-border, #29414e)' }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="px-5 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--corp-border, #29414e)' }}>
                            <div className="flex items-center gap-3">
                                <div style={{ fontSize: '1.6rem', fontWeight: 700, color: fg, letterSpacing: '0.02em' }}>{data.score}</div>
                                <div>
                                    <div style={{ fontSize: '0.95rem', fontWeight: 600 }}>Cluster health</div>
                                    <div className="text-xs opacity-60" style={{ textTransform: 'capitalize' }}>{data.band}</div>
                                </div>
                            </div>
                            <button onClick={onClose} className="opacity-60 hover:opacity-100 text-lg leading-none" aria-label="close">×</button>
                        </div>
                        <div className="p-5 space-y-3">
                            <div className="text-xs uppercase tracking-wide opacity-60">Factors</div>
                            <div className="space-y-1">
                                {(data.factors || []).map((f, i) => (
                                    <div key={i} className="flex items-center justify-between py-1.5" style={{ borderBottom: '1px solid var(--corp-border, #29414e)' }}>
                                        <span>{f.label}</span>
                                        <span className="flex items-center gap-3">
                                            <span className="opacity-80 text-sm">{f.value}</span>
                                            <span style={{
                                                fontVariantNumeric: 'tabular-nums', fontWeight: 600,
                                                color: f.delta < 0 ? '#f54f47' : '#60b515',
                                                minWidth: '36px', textAlign: 'right',
                                            }}>{f.delta < 0 ? f.delta : '0'}</span>
                                        </span>
                                    </div>
                                ))}
                            </div>
                            {Array.isArray(data.issues) && data.issues.length > 0 && (
                                <>
                                    <div className="text-xs uppercase tracking-wide opacity-60 mt-4">Issues</div>
                                    <ul className="text-sm space-y-1">
                                        {data.issues.map((iss, i) => (
                                            <li key={i} className="flex items-start gap-2">
                                                <span style={{ color: '#f54f47' }}>•</span><span>{iss}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </>
                            )}
                            {data.computed_at && (
                                <div className="text-xs opacity-50 mt-3">Computed: {new Date(data.computed_at).toLocaleString()}</div>
                            )}
                        </div>
                    </div>
                </div>
            );
        }
        try { window.PegaProxClusterHealthBadge = ClusterHealthBadge; } catch (_) {}

        // MK May 2026 — Proxmox API latency dashboard. Polls every 10s while open.
        // Shows P50/P95/P99 + sparkline + per-endpoint breakdown.
        function ApiLatencyDashboard({ clusterId, authFetch, apiUrl, t }) {
            const [data, setData] = React.useState(null);
            const [loading, setLoading] = React.useState(false);
            const [autoRefresh, setAutoRefresh] = React.useState(true);

            const fetchData = React.useCallback(async () => {
                if (!clusterId) return;
                setLoading(true);
                try {
                    const res = await authFetch(`${apiUrl}/clusters/${clusterId}/api-latency`);
                    if (res && res.ok) setData(await res.json());
                } catch (_) { /* keep last */ }
                finally { setLoading(false); }
            }, [clusterId, authFetch, apiUrl]);

            React.useEffect(() => {
                fetchData();
                if (!autoRefresh) return;
                const id = setInterval(fetchData, 10000);
                return () => clearInterval(id);
            }, [fetchData, autoRefresh]);

            // Sparkline svg
            const sparkline = React.useMemo(() => {
                const recent = data?.recent || [];
                if (recent.length < 2) return null;
                const W = 320, H = 60, P = 2;
                const xs = recent.length;
                const max = Math.max(...recent.map(r => r.duration_ms), 1);
                const points = recent.map((r, i) => {
                    const x = P + (i / (xs - 1)) * (W - 2 * P);
                    const y = H - P - (r.duration_ms / max) * (H - 2 * P);
                    return `${x.toFixed(1)},${y.toFixed(1)}`;
                }).join(' ');
                return { W, H, points, max };
            }, [data]);

            const colorFor = (ms) => ms > 1000 ? '#f54f47' : ms > 500 ? '#f7b428' : ms > 200 ? '#97bd34' : '#60b515';

            if (!data) {
                return (
                    <div className="rounded-lg p-6" style={{ background: 'var(--corp-surface, #1c2733)', border: '1px solid var(--corp-border, #29414e)' }}>
                        <div className="opacity-70 text-sm">{loading ? 'Loading…' : 'No data yet — refresh to start collection'}</div>
                    </div>
                );
            }

            return (
                <div className="space-y-4">
                    {/* headline tiles */}
                    <div className="flex flex-wrap gap-3 items-stretch">
                        <StatTile label="P50" value={`${data.p50}ms`} color={colorFor(data.p50)} />
                        <StatTile label="P95" value={`${data.p95}ms`} color={colorFor(data.p95)} />
                        <StatTile label="P99" value={`${data.p99}ms`} color={colorFor(data.p99)} />
                        <StatTile label="Max" value={`${data.max}ms`} color={colorFor(data.max)} />
                        <StatTile label="Avg" value={`${data.avg}ms`} color={colorFor(data.avg)} />
                        <StatTile label="Samples" value={data.samples} sub={`last ${Math.round((data.window_seconds || 300) / 60)}m`} />
                        <StatTile
                            label="Error rate"
                            value={`${data.error_rate}%`}
                            color={data.error_rate > 5 ? '#f54f47' : data.error_rate > 1 ? '#f7b428' : '#60b515'}
                        />
                        <div className="flex-grow" />
                        <button
                            onClick={() => setAutoRefresh(v => !v)}
                            className="px-3 py-1.5 text-xs rounded"
                            style={{
                                background: autoRefresh ? 'var(--corp-accent, #0078a8)' : 'var(--corp-surface-2, #29414e)',
                                color: '#fff', border: '1px solid var(--corp-border, #485764)',
                                alignSelf: 'flex-end', height: 'fit-content',
                            }}
                            title={autoRefresh ? 'Auto-refresh ON (10s)' : 'Auto-refresh OFF'}
                        >{autoRefresh ? 'auto · 10s' : 'paused'}</button>
                    </div>

                    {/* sparkline */}
                    {sparkline && (
                        <div className="rounded-lg p-4" style={{ background: 'var(--corp-surface, #1c2733)', border: '1px solid var(--corp-border, #29414e)' }}>
                            <div className="text-xs uppercase tracking-wide opacity-70 mb-2">Recent samples</div>
                            <svg width={sparkline.W} height={sparkline.H} style={{ display: 'block', maxWidth: '100%' }}>
                                <polyline
                                    fill="none"
                                    stroke="var(--corp-accent, #0078a8)"
                                    strokeWidth="1.5"
                                    points={sparkline.points}
                                />
                            </svg>
                            <div className="text-xs opacity-60 mt-1" style={{ fontVariantNumeric: 'tabular-nums' }}>
                                peak in window: {sparkline.max.toFixed(0)}ms
                            </div>
                        </div>
                    )}

                    {/* per-endpoint breakdown */}
                    <div className="rounded-lg overflow-hidden" style={{ background: 'var(--corp-surface, #1c2733)', border: '1px solid var(--corp-border, #29414e)' }}>
                        <div className="px-4 py-2 text-xs uppercase tracking-wide opacity-70" style={{ borderBottom: '1px solid var(--corp-border, #29414e)' }}>Top endpoints by total time</div>
                        <table className="w-full text-sm" style={{ tableLayout: 'fixed' }}>
                            <thead>
                                <tr style={{ background: 'var(--corp-surface-2, #29414e)' }}>
                                    <th className="px-4 py-2 text-left" style={{ width: '50%' }}>Endpoint</th>
                                    <th className="px-4 py-2 text-right">Calls</th>
                                    <th className="px-4 py-2 text-right">Avg ms</th>
                                    <th className="px-4 py-2 text-right">Max ms</th>
                                    <th className="px-4 py-2 text-right">Errors</th>
                                </tr>
                            </thead>
                            <tbody>
                                {(data.by_endpoint || []).map((e, i) => (
                                    <tr key={i} style={{ borderTop: '1px solid var(--corp-border, #29414e)' }}>
                                        <td className="px-4 py-1.5 font-mono text-xs truncate" title={e.endpoint}>{e.endpoint}</td>
                                        <td className="px-4 py-1.5 text-right" style={{ fontVariantNumeric: 'tabular-nums' }}>{e.count}</td>
                                        <td className="px-4 py-1.5 text-right" style={{ fontVariantNumeric: 'tabular-nums', color: colorFor(e.avg_ms) }}>{e.avg_ms}</td>
                                        <td className="px-4 py-1.5 text-right" style={{ fontVariantNumeric: 'tabular-nums', color: colorFor(e.max_ms) }}>{e.max_ms}</td>
                                        <td className="px-4 py-1.5 text-right" style={{ color: e.errors > 0 ? '#f54f47' : 'inherit', fontVariantNumeric: 'tabular-nums' }}>{e.errors || '—'}</td>
                                    </tr>
                                ))}
                                {(!data.by_endpoint || data.by_endpoint.length === 0) && (
                                    <tr><td colSpan="5" className="px-4 py-3 opacity-60 text-center">No samples yet</td></tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            );
        }
        try { window.PegaProxApiLatencyDashboard = ApiLatencyDashboard; } catch (_) {}

        // LW May 2026 — VM snapshot comparison modal. Opens with one snap pre-selected,
        // user picks the other via dropdown; backend returns the diff.
        function SnapshotCompareModal({ vm, clusterId, snapshots, initialA, initialB, onClose, authFetch, apiUrl }) {
            // Build options list — include 'current' as a synthetic entry
            const opts = React.useMemo(() => {
                const names = (snapshots || [])
                    .map(s => s.name)
                    .filter(n => n && n !== 'current');
                return [{ value: 'current', label: 'current (live config)' },
                        ...names.map(n => ({ value: n, label: n }))];
            }, [snapshots]);

            const [a, setA] = React.useState(initialA || 'current');
            const [b, setB] = React.useState(initialB || (opts[1]?.value || 'current'));
            const [diff, setDiff] = React.useState(null);
            const [loading, setLoading] = React.useState(false);
            const [error, setError] = React.useState(null);
            const [showSame, setShowSame] = React.useState(false);

            React.useEffect(() => {
                if (!a || !b || a === b) { setDiff(null); setError(a === b ? 'Pick two different snapshots' : null); return; }
                setLoading(true); setError(null);
                (async () => {
                    try {
                        const url = `${apiUrl}/clusters/${clusterId}/vms/${vm.node}/${vm.type}/${vm.vmid}/snapshots/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`;
                        const r = await authFetch(url);
                        if (!r || !r.ok) {
                            const msg = r ? (await r.json().catch(() => ({}))).error || `HTTP ${r.status}` : 'Network error';
                            setError(msg); setDiff(null);
                        } else {
                            setDiff(await r.json());
                        }
                    } catch (e) {
                        setError(e.message || String(e));
                    } finally { setLoading(false); }
                })();
            }, [a, b, vm.node, vm.type, vm.vmid, clusterId, apiUrl, authFetch]);

            React.useEffect(() => {
                const onKey = (e) => { if (e.key === 'Escape') onClose(); };
                window.addEventListener('keydown', onKey);
                return () => window.removeEventListener('keydown', onKey);
            }, [onClose]);

            const colorFor = (k) => k === 'added' ? '#60b515' : k === 'removed' ? '#f54f47' : k === 'changed' ? '#f7b428' : '#728b9a';
            const symbolFor = (k) => k === 'added' ? '+' : k === 'removed' ? '−' : k === 'changed' ? '~' : '=';
            const fmtVal = (v) => {
                if (v === undefined || v === null) return <span style={{ opacity: 0.5 }}>—</span>;
                if (typeof v === 'object') return JSON.stringify(v);
                return String(v);
            };
            const filteredDiffs = (diff?.diffs || []).filter(d => showSame || d.kind !== 'same');

            return (
                <div className="fixed inset-0 z-[10010] flex items-center justify-center p-4" style={{ background: 'rgba(8,14,24,0.72)' }} onClick={onClose}>
                    <div
                        className="rounded-lg shadow-2xl flex flex-col"
                        style={{
                            background: 'var(--corp-surface, #1c2733)',
                            color: 'var(--corp-text, #e9ecef)',
                            border: '1px solid var(--corp-border, #29414e)',
                            width: 'min(960px, 100vw - 32px)',
                            maxHeight: 'min(85vh, 800px)',
                        }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="px-5 py-3 flex items-center justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--corp-border, #29414e)' }}>
                            <div>
                                <div className="text-base font-semibold flex items-center gap-2">
                                    <Icons.Camera className="w-4 h-4" style={{ color: 'var(--corp-accent, #49afd9)' }} />
                                    Snapshot Compare — {vm.name || `${vm.type === 'qemu' ? 'VM' : 'CT'} ${vm.vmid}`}
                                </div>
                                {diff?.summary && (
                                    <div className="text-xs opacity-70 mt-0.5">
                                        <span style={{ color: '#60b515' }}>+{diff.summary.added}</span>{' '}
                                        <span style={{ color: '#f54f47' }}>−{diff.summary.removed}</span>{' '}
                                        <span style={{ color: '#f7b428' }}>~{diff.summary.changed}</span>{' '}
                                        <span className="opacity-60">·  {diff.summary.same} unchanged</span>
                                    </div>
                                )}
                            </div>
                            <button onClick={onClose} className="opacity-60 hover:opacity-100 text-lg leading-none" aria-label="close">×</button>
                        </div>

                        <div className="px-5 py-3 flex flex-wrap items-center gap-3 flex-shrink-0" style={{ borderBottom: '1px solid var(--corp-border, #29414e)' }}>
                            <label className="flex items-center gap-2 text-sm">
                                <span className="opacity-70">A:</span>
                                <select
                                    value={a}
                                    onChange={(e) => setA(e.target.value)}
                                    className="px-2 py-1 text-sm"
                                    style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text, #e9ecef)', border: '1px solid var(--corp-border, #485764)' }}
                                >
                                    {opts.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                                </select>
                            </label>
                            <button
                                onClick={() => { const tmp = a; setA(b); setB(tmp); }}
                                className="px-2 py-1 text-xs rounded"
                                style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }}
                                title="Swap A and B"
                            >⇆</button>
                            <label className="flex items-center gap-2 text-sm">
                                <span className="opacity-70">B:</span>
                                <select
                                    value={b}
                                    onChange={(e) => setB(e.target.value)}
                                    className="px-2 py-1 text-sm"
                                    style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text, #e9ecef)', border: '1px solid var(--corp-border, #485764)' }}
                                >
                                    {opts.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                                </select>
                            </label>
                            <div className="flex-grow" />
                            <label className="flex items-center gap-2 text-xs opacity-80 cursor-pointer">
                                <input type="checkbox" checked={showSame} onChange={(e) => setShowSame(e.target.checked)} />
                                Show unchanged
                            </label>
                        </div>

                        <div className="flex-1 overflow-auto" style={{ minHeight: 200 }}>
                            {loading && <div className="p-6 text-center opacity-70">Loading diff…</div>}
                            {error && <div className="p-6 text-center" style={{ color: '#f54f47' }}>{error}</div>}
                            {!loading && !error && diff && (
                                <table className="w-full text-sm" style={{ tableLayout: 'fixed', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}>
                                    <thead style={{ position: 'sticky', top: 0, background: 'var(--corp-surface-2, #29414e)' }}>
                                        <tr>
                                            <th className="px-3 py-2 text-left" style={{ width: '24px' }}></th>
                                            <th className="px-3 py-2 text-left" style={{ width: '20%' }}>Key</th>
                                            <th className="px-3 py-2 text-left">{a}</th>
                                            <th className="px-3 py-2 text-left">{b}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {filteredDiffs.map((d, i) => (
                                            <tr key={i} style={{
                                                borderTop: '1px solid var(--corp-border, #29414e)',
                                                background: d.kind === 'same' ? 'transparent'
                                                            : d.kind === 'added' ? 'rgba(96,181,21,0.06)'
                                                            : d.kind === 'removed' ? 'rgba(245,79,71,0.06)'
                                                            : 'rgba(247,180,40,0.06)',
                                            }}>
                                                <td className="px-3 py-1.5 text-center" style={{ color: colorFor(d.kind), fontWeight: 700 }}>
                                                    {symbolFor(d.kind)}
                                                </td>
                                                <td className="px-3 py-1.5" style={{ wordBreak: 'break-all' }}>{d.key}</td>
                                                <td className="px-3 py-1.5" style={{ wordBreak: 'break-all', color: d.kind === 'removed' || d.kind === 'changed' ? '#f54f47' : 'inherit' }}>{fmtVal(d.a)}</td>
                                                <td className="px-3 py-1.5" style={{ wordBreak: 'break-all', color: d.kind === 'added' || d.kind === 'changed' ? '#60b515' : 'inherit' }}>{fmtVal(d.b)}</td>
                                            </tr>
                                        ))}
                                        {filteredDiffs.length === 0 && (
                                            <tr><td colSpan="4" className="px-3 py-6 text-center opacity-60">{showSame ? 'No keys' : 'No differences (toggle "Show unchanged" to see all)'}</td></tr>
                                        )}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    </div>
                </div>
            );
        }
        try { window.PegaProxSnapshotCompareModal = SnapshotCompareModal; } catch (_) {}

        // ============================================================
        // NS May 2026 — PBS UX kit. All components self-contained, drop-in.
        // ============================================================

        // PBS Health Badge — mirrors ClusterHealthBadge but for /api/pbs/<id>/health
        function PbsHealthBadge({ pbsId, authFetch, apiUrl }) {
            const [data, setData] = React.useState(null);
            const [showDetails, setShowDetails] = React.useState(false);
            const [hovering, setHovering] = React.useState(false);
            const fetchHealth = React.useCallback(async () => {
                if (!pbsId) return;
                try {
                    const r = await authFetch(`${apiUrl}/pbs/${pbsId}/health`);
                    if (r && r.ok) setData(await r.json());
                } catch (_) { /* keep last */ }
            }, [pbsId, authFetch, apiUrl]);
            React.useEffect(() => {
                fetchHealth();
                const id = setInterval(fetchHealth, 60000);
                return () => clearInterval(id);
            }, [fetchHealth]);
            if (!data) return null;
            const colors = {
                excellent: { bg: 'rgba(96,181,21,0.18)', fg: '#60b515', bd: 'rgba(96,181,21,0.4)' },
                good: { bg: 'rgba(151,189,52,0.18)', fg: '#97bd34', bd: 'rgba(151,189,52,0.4)' },
                warning: { bg: 'rgba(247,180,40,0.18)', fg: '#f7b428', bd: 'rgba(247,180,40,0.4)' },
                degraded: { bg: 'rgba(238,142,38,0.18)', fg: '#ee8e26', bd: 'rgba(238,142,38,0.4)' },
                critical: { bg: 'rgba(245,79,71,0.18)', fg: '#f54f47', bd: 'rgba(245,79,71,0.4)' },
            };
            const c = colors[data.band] || colors.warning;
            return (
                <>
                    <span
                        className="corp-badge"
                        style={{ background: c.bg, color: c.fg, border: `1px solid ${c.bd}`, cursor: 'pointer',
                                 position: 'relative', userSelect: 'none', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                        onClick={() => setShowDetails(true)}
                        onMouseEnter={() => setHovering(true)}
                        onMouseLeave={() => setHovering(false)}
                        title="PBS health — click for breakdown"
                    >
                        <span style={{ fontWeight: 700 }}>{data.score}</span>
                        <span style={{ opacity: 0.75, fontSize: '0.7rem' }}>health</span>
                        {hovering && Array.isArray(data.factors) && data.factors.length > 0 && (
                            <div style={{
                                position: 'absolute', top: '100%', right: 0, marginTop: '4px',
                                background: 'var(--corp-surface, #1c2733)', border: '1px solid var(--corp-border, #29414e)',
                                borderRadius: '4px', padding: '8px 10px', color: 'var(--corp-text)',
                                fontSize: '0.72rem', minWidth: '220px', zIndex: 200,
                                boxShadow: '0 4px 12px rgba(0,0,0,0.3)', textAlign: 'left', whiteSpace: 'nowrap',
                            }}>
                                {data.factors.map((f, i) => (
                                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', padding: '2px 0' }}>
                                        <span style={{ opacity: 0.8 }}>{f.label}</span>
                                        <span style={{ color: f.delta < 0 ? '#f54f47' : '#60b515' }}>{f.delta < 0 ? f.delta : 'ok'}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </span>
                    {showDetails && <ClusterHealthModal data={data} onClose={() => setShowDetails(false)} />}
                </>
            );
        }
        try { window.PegaProxPbsHealthBadge = PbsHealthBadge; } catch (_) {}

        // Backup Status Pill for VM list rows
        function BackupStatusPill({ status, lastAgeHours, encrypted, verifyAgeHours, count30d }) {
            const map = {
                ok:    { bg: 'rgba(96,181,21,0.15)',  fg: '#60b515', label: 'fresh',  icon: '✓' },
                warn:  { bg: 'rgba(247,180,40,0.15)', fg: '#f7b428', label: '7d',     icon: '⚠' },
                stale: { bg: 'rgba(245,79,71,0.15)',  fg: '#f54f47', label: 'stale',  icon: '✗' },
                none:  { bg: 'rgba(150,150,150,0.15)',fg: '#999',    label: 'none',   icon: '—' },
            };
            const c = map[status] || map.none;
            const tip = (lastAgeHours == null
                ? 'No backups found'
                : lastAgeHours < 48
                    ? `Last backup ${lastAgeHours.toFixed(1)}h ago`
                    : `Last backup ${(lastAgeHours/24).toFixed(1)}d ago`)
                + (count30d ? ` · ${count30d} in last 30d` : '')
                + (verifyAgeHours != null ? ` · verified ${(verifyAgeHours/24).toFixed(1)}d ago` : ' · not verified');
            return (
                <span title={tip}
                    style={{
                        display: 'inline-flex', alignItems: 'center', gap: '3px',
                        background: c.bg, color: c.fg,
                        padding: '1px 6px', borderRadius: '3px', fontSize: '11px',
                        fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap',
                    }}
                >
                    <span>{c.icon}</span>
                    <span>{c.label}</span>
                    {encrypted && <span style={{ opacity: 0.8 }}>🔒</span>}
                    {verifyAgeHours != null && verifyAgeHours < 24 * 14 && <span style={{ opacity: 0.8 }}>✓v</span>}
                </span>
            );
        }
        try { window.PegaProxBackupStatusPill = BackupStatusPill; } catch (_) {}

        // Live Backup Progress Pane — tails a UPID's task log
        function BackupProgressPane({ clusterId, upid, node, authFetch, apiUrl, onClose }) {
            const [lines, setLines] = React.useState([]);
            const [done, setDone] = React.useState(false);
            const [exitstatus, setExitstatus] = React.useState(null);
            const [throughput, setThroughput] = React.useState([]);  // {ts, mbps}
            const lastByteRef = React.useRef({ ts: 0, bytes: 0 });

            React.useEffect(() => {
                if (!upid || !node) return;
                let cancelled = false;
                let startLine = 0;
                const tick = async () => {
                    try {
                        const r = await authFetch(`${apiUrl}/clusters/${clusterId}/nodes/${node}/tasks/${encodeURIComponent(upid)}/log?start=${startLine}`);
                        if (r && r.ok) {
                            const data = await r.json();
                            const arr = Array.isArray(data) ? data : (data.data || []);
                            if (arr.length) {
                                if (cancelled) return;
                                setLines(prev => [...prev, ...arr.map(l => l.t || l)]);
                                startLine += arr.length;
                                // throughput sniff: look for "INFO: ... read X.X GiB/s" or "transferred"
                                const recent = arr.map(l => l.t || l).join('\n');
                                const m = recent.match(/(\d+(?:\.\d+)?)\s*(MiB|GiB)\/s/);
                                if (m) {
                                    const mbps = parseFloat(m[1]) * (m[2] === 'GiB' ? 1024 : 1);
                                    setThroughput(prev => [...prev.slice(-29), { ts: Date.now(), mbps }]);
                                }
                            }
                        }
                        // Status check
                        const sr = await authFetch(`${apiUrl}/clusters/${clusterId}/nodes/${node}/tasks/${encodeURIComponent(upid)}/status`);
                        if (sr && sr.ok) {
                            const s = await sr.json();
                            if (s.status === 'stopped' || s.exitstatus) {
                                if (cancelled) return;
                                setDone(true);
                                setExitstatus(s.exitstatus || 'stopped');
                                return;
                            }
                        }
                    } catch (e) { /* keep polling */ }
                    if (!cancelled) setTimeout(tick, 2000);
                };
                tick();
                return () => { cancelled = true; };
            }, [upid, node, clusterId, authFetch, apiUrl]);

            const peakMbps = throughput.length ? Math.max(...throughput.map(t => t.mbps)) : 0;

            return (
                <div className="fixed bottom-0 right-4 z-[150]"
                    style={{ width: 'min(720px, 95vw)', maxHeight: '60vh',
                             background: 'var(--corp-surface, #1c2733)',
                             border: '1px solid var(--corp-border, #29414e)',
                             borderBottom: 'none', borderTopLeftRadius: '8px', borderTopRightRadius: '8px',
                             boxShadow: '0 -4px 16px rgba(0,0,0,0.4)',
                             color: 'var(--corp-text, #e9ecef)',
                             display: 'flex', flexDirection: 'column' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                  padding: '8px 12px', borderBottom: '1px solid var(--corp-border)' }}>
                        <div className="flex items-center gap-2">
                            <Icons.Clock className="w-4 h-4" style={{ color: done ? (exitstatus === 'OK' ? '#60b515' : '#f54f47') : '#f7b428' }} />
                            <span className="font-medium text-sm">Backup {done ? (exitstatus === 'OK' ? 'completed' : `failed (${exitstatus})`) : 'in progress…'}</span>
                            {throughput.length > 0 && (
                                <span className="text-xs opacity-70" style={{ fontVariantNumeric: 'tabular-nums' }}>
                                    {throughput[throughput.length - 1].mbps.toFixed(1)} MiB/s · peak {peakMbps.toFixed(1)}
                                </span>
                            )}
                        </div>
                        <button onClick={onClose} className="opacity-60 hover:opacity-100 leading-none" style={{fontSize:'18px'}}>×</button>
                    </div>
                    {throughput.length > 1 && (
                        <div style={{ padding: '4px 12px' }}>
                            <svg width="100%" height="28" preserveAspectRatio="none" viewBox={`0 0 ${throughput.length - 1} 28`}>
                                <polyline fill="none" stroke="var(--corp-accent, #0078a8)" strokeWidth="1.2"
                                    points={throughput.map((t, i) => `${i},${28 - (t.mbps / Math.max(peakMbps, 1)) * 26}`).join(' ')} />
                            </svg>
                        </div>
                    )}
                    <div style={{ flex: 1, overflowY: 'auto', padding: '8px 12px',
                                  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                                  fontSize: '11.5px', whiteSpace: 'pre-wrap', lineHeight: '1.4' }}>
                        {lines.length === 0 ? <span className="opacity-50">Waiting for output…</span>
                            : lines.map((l, i) => (
                                <div key={i} style={{
                                    color: /ERROR|FAIL/i.test(l) ? '#f54f47'
                                         : /WARN/i.test(l)        ? '#f7b428'
                                         : /INFO/i.test(l)        ? 'inherit'
                                         : '#728b9a',
                                }}>{l}</div>
                            ))}
                    </div>
                </div>
            );
        }
        try { window.PegaProxBackupProgressPane = BackupProgressPane; } catch (_) {}

        // PBS Capacity Forecast Tile
        function PbsCapacityForecast({ pbsId, authFetch, apiUrl }) {
            const [data, setData] = React.useState(null);
            React.useEffect(() => {
                if (!pbsId) return;
                let cancelled = false;
                (async () => {
                    try {
                        const r = await authFetch(`${apiUrl}/pbs/${pbsId}/capacity-forecast`);
                        if (r && r.ok && !cancelled) setData(await r.json());
                    } catch (_) {}
                })();
                return () => { cancelled = true; };
            }, [pbsId, authFetch, apiUrl]);
            if (!data || data.length === 0) return null;
            return (
                <div className="rounded-md p-3" style={{ background: 'var(--corp-surface, #1c2733)', border: '1px solid var(--corp-border, #29414e)' }}>
                    <div className="text-xs uppercase tracking-wide opacity-70 mb-2">Capacity forecast</div>
                    <div className="space-y-2">
                        {data.map(d => {
                            const days = d.eta_days_to_full;
                            const color = days == null ? '#728b9a' : days < 14 ? '#f54f47' : days < 60 ? '#f7b428' : '#60b515';
                            return (
                                <div key={d.store} className="flex items-center justify-between text-sm">
                                    <span className="font-mono">{d.store}</span>
                                    <span className="flex items-center gap-3">
                                        <span style={{ fontVariantNumeric: 'tabular-nums', opacity: 0.8 }}>{d.used_pct}%</span>
                                        {days != null ? (
                                            <span style={{ color, fontVariantNumeric: 'tabular-nums' }}
                                                title={`Slope: ${d.slope_pct_per_day}% / day, ${d.samples} samples`}>
                                                {days < 1 ? '<1d' : days < 365 ? `${days.toFixed(0)}d` : '>1y'}
                                            </span>
                                        ) : (
                                            <span style={{ opacity: 0.5 }}>—</span>
                                        )}
                                    </span>
                                </div>
                            );
                        })}
                    </div>
                </div>
            );
        }
        try { window.PegaProxPbsCapacityForecast = PbsCapacityForecast; } catch (_) {}

        // Storage-Add Pre-flight Indicator
        function StoragePreflightCheck({ clusterId, config, authFetch, apiUrl, onResult }) {
            const [state, setState] = React.useState({ status: 'idle', issues: [], info: {} });
            const run = async () => {
                if (config.type !== 'pbs') return;
                setState({ status: 'checking', issues: [], info: {} });
                try {
                    const r = await authFetch(`${apiUrl}/clusters/${clusterId}/storage-preflight`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(config),
                    });
                    if (r && r.ok) {
                        const j = await r.json();
                        const next = { status: j.ok ? 'ok' : 'fail', issues: j.issues || [], info: j.info || {} };
                        setState(next);
                        onResult?.(next);
                    } else {
                        setState({ status: 'error', issues: [`HTTP ${r?.status}`], info: {} });
                    }
                } catch (e) {
                    setState({ status: 'error', issues: [String(e)], info: {} });
                }
            };
            return (
                <div style={{ background: 'var(--corp-surface-2, #29414e)', padding: '8px 10px', borderRadius: '4px', fontSize: '12px' }}>
                    <div className="flex items-center justify-between">
                        <span className="opacity-80">Pre-flight check (PBS)</span>
                        <button onClick={run} disabled={state.status === 'checking'}
                            style={{ background: 'var(--corp-accent, #0078a8)', color: '#fff', padding: '2px 8px',
                                     borderRadius: '3px', border: 'none', cursor: 'pointer',
                                     opacity: state.status === 'checking' ? 0.5 : 1 }}>
                            {state.status === 'checking' ? 'Checking…' : 'Run check'}
                        </button>
                    </div>
                    {state.status === 'ok' && <div style={{ color: '#60b515', marginTop: '4px' }}>✓ All checks passed. Live fingerprint matches; auth ok; datastore exists.</div>}
                    {state.status === 'fail' && (
                        <ul style={{ marginTop: '4px', paddingLeft: '18px' }}>
                            {state.issues.map((iss, i) => <li key={i} style={{ color: '#f54f47' }}>{iss}</li>)}
                        </ul>
                    )}
                    {state.info.live_fingerprint && state.status !== 'ok' && (
                        <div style={{ marginTop: '4px', opacity: 0.7, fontFamily: 'ui-monospace, monospace', fontSize: '11px', wordBreak: 'break-all' }}>
                            Live fingerprint: {state.info.live_fingerprint}
                        </div>
                    )}
                </div>
            );
        }
        try { window.PegaProxStoragePreflightCheck = StoragePreflightCheck; } catch (_) {}

        // Auto-Fingerprint button — fetches the cert fingerprint via probe endpoint
        function FingerprintFetcher({ host, port, authFetch, apiUrl, onFetched }) {
            const [busy, setBusy] = React.useState(false);
            const [error, setError] = React.useState(null);
            const fetchIt = async () => {
                if (!host) { setError('host required'); return; }
                setBusy(true); setError(null);
                try {
                    const r = await authFetch(`${apiUrl}/pbs/probe-fingerprint`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ host, port: port || 8007 }),
                    });
                    const j = await r.json();
                    if (r.ok && j.fingerprint) {
                        onFetched?.(j.fingerprint);
                    } else {
                        setError(j.error || `HTTP ${r.status}`);
                    }
                } catch (e) { setError(String(e)); }
                finally { setBusy(false); }
            };
            return (
                <span className="inline-flex items-center gap-2">
                    <button type="button" onClick={fetchIt} disabled={busy || !host}
                        style={{ background: 'var(--corp-accent, #0078a8)', color: '#fff', padding: '4px 10px',
                                 borderRadius: '3px', border: 'none', cursor: 'pointer', fontSize: '12px',
                                 opacity: (busy || !host) ? 0.5 : 1 }}
                        title="Connect to host and capture the TLS fingerprint">
                        {busy ? '…' : 'Auto-fetch'}
                    </button>
                    {error && <span style={{ color: '#f54f47', fontSize: '11px' }}>{error}</span>}
                </span>
            );
        }
        try { window.PegaProxFingerprintFetcher = FingerprintFetcher; } catch (_) {}

        // Backup Restore Wizard — three-mode (new/overwrite/test)
        function BackupRestoreWizard({ clusterId, snapshot, datastoreName, nodes, storages, authFetch, apiUrl, onClose, onStarted }) {
            // snapshot: {volid, vmid, type, backup_time}
            const [mode, setMode] = React.useState('new');
            const [targetNode, setTargetNode] = React.useState(nodes?.[0] || '');
            const [targetVmid, setTargetVmid] = React.useState(snapshot?.vmid ? snapshot.vmid + 1000 : 999);
            const [targetStorage, setTargetStorage] = React.useState('');
            const [running, setRunning] = React.useState(false);
            const [error, setError] = React.useState(null);

            // suggested next free vmid for "new" mode
            React.useEffect(() => {
                if (mode !== 'new' || !clusterId) return;
                (async () => {
                    try {
                        const r = await authFetch(`${apiUrl}/clusters/${clusterId}/next-vmid`);
                        if (r && r.ok) {
                            const j = await r.json();
                            if (j.vmid) setTargetVmid(j.vmid);
                        }
                    } catch (_) {}
                })();
            }, [mode, clusterId]);

            const submit = async () => {
                setRunning(true); setError(null);
                try {
                    const body = {
                        volid: snapshot.volid || `${datastoreName}:backup/${snapshot.type}/${snapshot.vmid}/${snapshot.backup_time_iso || ''}`,
                        target_node: targetNode,
                        target_vmid: parseInt(targetVmid, 10),
                        mode,
                    };
                    if (targetStorage) body.target_storage = targetStorage;
                    const r = await authFetch(`${apiUrl}/clusters/${clusterId}/backup-restore`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body),
                    });
                    const j = await r.json();
                    if (r.ok) {
                        onStarted?.(j);
                        onClose();
                    } else {
                        setError(j.error || `HTTP ${r.status}`);
                    }
                } catch (e) { setError(String(e)); }
                finally { setRunning(false); }
            };

            const modeDescs = {
                new: 'Restore as a new VM with the chosen VMID. Original VM stays untouched.',
                overwrite: 'Overwrite an existing VM with the same VMID. Existing config + disks will be lost.',
                test: 'Test-restore — restore + boot, then keep the test VM (no auto-cleanup). Useful for DR drills.',
            };

            return (
                <div className="fixed inset-0 z-[10010] flex items-center justify-center p-4" style={{ background: 'rgba(8,14,24,0.72)' }} onClick={onClose}>
                    <div
                        className="rounded-lg shadow-2xl w-full max-w-lg"
                        style={{ background: 'var(--corp-surface, #1c2733)', color: 'var(--corp-text, #e9ecef)', border: '1px solid var(--corp-border, #29414e)' }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="px-5 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--corp-border, #29414e)' }}>
                            <div className="text-base font-semibold">Restore backup</div>
                            <button onClick={onClose} className="opacity-60 hover:opacity-100 leading-none" style={{fontSize:'18px'}}>×</button>
                        </div>
                        <div className="p-5 space-y-3">
                            <div className="text-xs opacity-70">Source: {snapshot?.volid || '(unknown)'}</div>

                            <div>
                                <div className="text-xs uppercase tracking-wide opacity-60 mb-1">Mode</div>
                                <div className="grid grid-cols-3 gap-2">
                                    {['new', 'overwrite', 'test'].map(m => (
                                        <button key={m} type="button" onClick={() => setMode(m)}
                                            className="px-2 py-1 text-xs"
                                            style={{
                                                background: mode === m ? 'var(--corp-accent, #0078a8)' : 'var(--corp-surface-2, #29414e)',
                                                color: '#fff', border: '1px solid var(--corp-border, #485764)',
                                                borderRadius: '3px',
                                                fontWeight: mode === m ? 600 : 400,
                                            }}>
                                            {m}
                                        </button>
                                    ))}
                                </div>
                                <div className="text-xs opacity-60 mt-1">{modeDescs[mode]}</div>
                            </div>

                            <div>
                                <div className="text-xs uppercase tracking-wide opacity-60 mb-1">Target node</div>
                                <select value={targetNode} onChange={e => setTargetNode(e.target.value)}
                                    className="w-full px-2 py-1.5 text-sm"
                                    style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }}>
                                    {(nodes || []).map(n => <option key={n} value={n}>{n}</option>)}
                                </select>
                            </div>

                            <div>
                                <div className="text-xs uppercase tracking-wide opacity-60 mb-1">Target VMID</div>
                                <input type="number" value={targetVmid} onChange={e => setTargetVmid(e.target.value)}
                                    className="w-full px-2 py-1.5 text-sm"
                                    style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }} />
                            </div>

                            <div>
                                <div className="text-xs uppercase tracking-wide opacity-60 mb-1">Target storage (optional)</div>
                                <select value={targetStorage} onChange={e => setTargetStorage(e.target.value)}
                                    className="w-full px-2 py-1.5 text-sm"
                                    style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }}>
                                    <option value="">— use default from backup —</option>
                                    {(storages || []).map(s => <option key={s} value={s}>{s}</option>)}
                                </select>
                            </div>

                            {error && <div style={{ color: '#f54f47', fontSize: '12px' }}>{error}</div>}

                            <div className="flex justify-end gap-2 pt-2" style={{ borderTop: '1px solid var(--corp-border, #29414e)' }}>
                                <button type="button" onClick={onClose}
                                    className="px-3 py-1.5 text-sm"
                                    style={{ background: 'transparent', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)', borderRadius: '3px' }}>
                                    Cancel
                                </button>
                                <button type="button" onClick={submit} disabled={running || !targetNode || !targetVmid}
                                    className="px-3 py-1.5 text-sm font-medium"
                                    style={{ background: mode === 'overwrite' ? '#b94a3a' : 'var(--corp-accent, #0078a8)',
                                             color: '#fff', border: 'none', borderRadius: '3px',
                                             opacity: (running || !targetNode || !targetVmid) ? 0.5 : 1 }}>
                                    {running ? 'Starting…' : `Start restore (${mode})`}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            );
        }
        try { window.PegaProxBackupRestoreWizard = BackupRestoreWizard; } catch (_) {}

        // LW May 2026 — Encryption key generator. Generates server-side, shows
        // once, lets the user download the JSON envelope + a printable sheet.
        function EncryptionKeyModal({ authFetch, apiUrl, onClose }) {
            const [data, setData] = React.useState(null);
            const [busy, setBusy] = React.useState(false);
            const [err, setErr] = React.useState(null);

            const generate = async () => {
                setBusy(true); setErr(null);
                try {
                    const r = await authFetch(`${apiUrl}/pbs/encryption-key/generate`, { method: 'POST' });
                    const j = await r.json();
                    if (r.ok) setData(j);
                    else setErr(j.error || `HTTP ${r.status}`);
                } catch (e) { setErr(String(e)); }
                finally { setBusy(false); }
            };

            const download = (filename, content, type = 'text/plain') => {
                const blob = new Blob([content], { type });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = filename;
                document.body.appendChild(a); a.click();
                setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 200);
            };

            const printSheet = () => {
                const w = window.open('', 'pbs-key', 'width=720,height=900');
                if (!w) return;
                const safe = (s) => String(s).replace(/[<&>]/g, c => ({'<':'&lt;','&':'&amp;','>':'&gt;'})[c]);
                w.document.write(`<!DOCTYPE html><html><head><title>PBS Encryption Key Recovery Sheet</title>
<style>body{font-family:ui-monospace,monospace;font-size:11pt;padding:24px;color:#000}
h1{font-size:14pt;margin-bottom:6px}.warn{color:#a00;font-weight:bold}
pre{white-space:pre-wrap;word-break:break-all;border:1px solid #ccc;padding:12px;background:#f7f7f7}
@media print{body{padding:0}}</style></head><body>
<h1>PBS Encryption Key — Recovery Sheet</h1>
<p class="warn">⚠ Without this key, all backups encrypted with it are UNRECOVERABLE. Store offline.</p>
<pre>${safe(data?.recovery_sheet || '')}</pre>
<p>JSON envelope (paste into /etc/pve/priv/storage/&lt;id&gt;.enc):</p>
<pre>${safe(JSON.stringify(data?.key_json, null, 2))}</pre>
</body></html>`);
                w.document.close();
                setTimeout(() => w.print(), 300);
            };

            return (
                <div className="fixed inset-0 z-[10010] flex items-center justify-center p-4" style={{ background: 'rgba(8,14,24,0.72)' }} onClick={onClose}>
                    <div
                        className="rounded-lg shadow-2xl w-full max-w-2xl"
                        style={{ background: 'var(--corp-surface, #1c2733)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #29414e)' }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="px-5 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--corp-border, #29414e)' }}>
                            <div className="text-base font-semibold flex items-center gap-2">
                                <Icons.Lock className="w-4 h-4" />
                                PBS Encryption Key
                            </div>
                            <button onClick={onClose} className="opacity-60 hover:opacity-100 leading-none" style={{fontSize:'18px'}}>×</button>
                        </div>
                        <div className="p-5 space-y-3">
                            {!data && (
                                <>
                                    <div className="text-sm opacity-80">
                                        Generates a fresh AES-256 encryption key in PBS format. Without this key,
                                        encrypted backups are unrecoverable — store offline.
                                    </div>
                                    <div style={{ background: 'rgba(245,79,71,0.08)', border: '1px solid rgba(245,79,71,0.4)',
                                                  borderRadius: '4px', padding: '8px 10px', fontSize: '12px', color: '#f54f47' }}>
                                        ⚠ The key is shown <strong>once</strong>. PegaProx does not retain a copy.
                                    </div>
                                    {err && <div style={{ color: '#f54f47', fontSize: '12px' }}>{err}</div>}
                                    <div className="flex justify-end">
                                        <button onClick={generate} disabled={busy}
                                            className="px-4 py-2 text-sm font-medium"
                                            style={{ background: 'var(--corp-accent, #0078a8)', color: '#fff', border: 'none', borderRadius: '3px',
                                                     opacity: busy ? 0.5 : 1 }}>
                                            {busy ? 'Generating…' : 'Generate key'}
                                        </button>
                                    </div>
                                </>
                            )}
                            {data && (
                                <>
                                    <div className="text-xs uppercase tracking-wide opacity-70">Fingerprint</div>
                                    <div className="font-mono text-xs" style={{ wordBreak: 'break-all', padding: '6px 8px', background: 'var(--corp-surface-2, #29414e)', borderRadius: '3px' }}>
                                        {data.fingerprint}
                                    </div>
                                    <div className="text-xs uppercase tracking-wide opacity-70 mt-3">Recovery sheet (printable)</div>
                                    <pre style={{ fontSize: '10.5px', maxHeight: '260px', overflowY: 'auto',
                                                  padding: '10px 12px', background: 'var(--corp-surface-2, #29414e)',
                                                  borderRadius: '3px', whiteSpace: 'pre-wrap' }}>{data.recovery_sheet}</pre>
                                    <div className="flex justify-end gap-2 pt-2" style={{ borderTop: '1px solid var(--corp-border, #29414e)' }}>
                                        <button onClick={() => download(`pbs-key-${data.fingerprint.slice(0,8)}.json`, JSON.stringify(data.key_json, null, 2), 'application/json')}
                                            className="px-3 py-1.5 text-sm"
                                            style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)', borderRadius: '3px' }}>
                                            Download JSON
                                        </button>
                                        <button onClick={() => download(`pbs-key-recovery-${data.fingerprint.slice(0,8)}.txt`, data.recovery_sheet)}
                                            className="px-3 py-1.5 text-sm"
                                            style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)', borderRadius: '3px' }}>
                                            Download .txt
                                        </button>
                                        <button onClick={printSheet}
                                            className="px-3 py-1.5 text-sm font-medium"
                                            style={{ background: 'var(--corp-accent, #0078a8)', color: '#fff', border: 'none', borderRadius: '3px' }}>
                                            Print recovery sheet
                                        </button>
                                    </div>
                                </>
                            )}
                        </div>
                    </div>
                </div>
            );
        }
        try { window.PegaProxEncryptionKeyModal = EncryptionKeyModal; } catch (_) {}

        // NS May 2026 — settings panel for the auto-verify schedule.
        // Backend at /api/pbs/verify-schedule (GET/PUT). Single dialog toggle.
        function VerifyScheduleModal({ authFetch, apiUrl, onClose }) {
            const [cfg, setCfg] = React.useState(null);
            const [busy, setBusy] = React.useState(false);
            const [err, setErr] = React.useState(null);
            React.useEffect(() => {
                (async () => {
                    try {
                        const r = await authFetch(`${apiUrl}/pbs/verify-schedule`);
                        if (r && r.ok) setCfg(await r.json());
                        else setErr(`HTTP ${r?.status}`);
                    } catch (e) { setErr(String(e)); }
                })();
                const onKey = (e) => { if (e.key === 'Escape') onClose(); };
                window.addEventListener('keydown', onKey);
                return () => window.removeEventListener('keydown', onKey);
            }, [authFetch, apiUrl, onClose]);
            const save = async () => {
                setBusy(true); setErr(null);
                try {
                    const r = await authFetch(`${apiUrl}/pbs/verify-schedule`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(cfg),
                    });
                    if (r && r.ok) onClose();
                    else setErr(`HTTP ${r?.status}`);
                } catch (e) { setErr(String(e)); }
                finally { setBusy(false); }
            };
            const update = (k, v) => setCfg(c => ({ ...c, [k]: v }));
            return (
                <div className="fixed inset-0 z-[10010] flex items-center justify-center p-4" style={{ background: 'rgba(8,14,24,0.72)' }} onClick={onClose}>
                    <div
                        className="rounded-lg shadow-2xl w-full max-w-md"
                        style={{ background: 'var(--corp-surface, #1c2733)', color: 'var(--corp-text, #e9ecef)', border: '1px solid var(--corp-border, #29414e)' }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="px-5 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--corp-border, #29414e)' }}>
                            <div className="text-base font-semibold flex items-center gap-2">
                                <Icons.Clock className="w-4 h-4" />
                                Auto Backup Verification
                            </div>
                            <button onClick={onClose} className="opacity-60 hover:opacity-100 leading-none" style={{fontSize:'18px'}}>×</button>
                        </div>
                        {!cfg ? (
                            <div className="p-6 text-center opacity-70">{err || 'Loading…'}</div>
                        ) : (
                            <div className="p-5 space-y-3">
                                <p className="text-xs opacity-70">
                                    Schedules a weekly backup-verification: a small set of recent snapshots is restored to scratch, booted, then cleaned up. Catches silent backup corruption.
                                </p>
                                <label className="flex items-center gap-3">
                                    <input type="checkbox" checked={!!cfg.enabled} onChange={(e) => update('enabled', e.target.checked)} />
                                    <span>Enable scheduled auto-verification</span>
                                </label>
                                <div style={{ opacity: cfg.enabled ? 1 : 0.5 }}>
                                    <div className="grid grid-cols-2 gap-3">
                                        <label className="text-sm">
                                            <div className="opacity-70 mb-1">Day</div>
                                            <select value={cfg.day || 'sun'} onChange={(e) => update('day', e.target.value)}
                                                className="w-full px-2 py-1.5 text-sm" disabled={!cfg.enabled}
                                                style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }}>
                                                {['mon','tue','wed','thu','fri','sat','sun'].map(d => <option key={d} value={d}>{d.toUpperCase()}</option>)}
                                            </select>
                                        </label>
                                        <label className="text-sm">
                                            <div className="opacity-70 mb-1">Hour (0-23)</div>
                                            <input type="number" min="0" max="23" value={cfg.hour ?? 4}
                                                onChange={(e) => update('hour', Math.max(0, Math.min(23, parseInt(e.target.value) || 0)))}
                                                disabled={!cfg.enabled}
                                                className="w-full px-2 py-1.5 text-sm"
                                                style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }} />
                                        </label>
                                    </div>
                                    <label className="text-sm block mt-3">
                                        <div className="opacity-70 mb-1">Snapshots per run (1-50)</div>
                                        <input type="number" min="1" max="50" value={cfg.weekly_count ?? 5}
                                            onChange={(e) => update('weekly_count', Math.max(1, Math.min(50, parseInt(e.target.value) || 1)))}
                                            disabled={!cfg.enabled}
                                            className="w-full px-2 py-1.5 text-sm"
                                            style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }} />
                                    </label>
                                    <label className="text-sm block mt-3">
                                        <div className="opacity-70 mb-1">Scope</div>
                                        <select value={cfg.scope || 'latest_per_vm'} onChange={(e) => update('scope', e.target.value)}
                                            disabled={!cfg.enabled}
                                            className="w-full px-2 py-1.5 text-sm"
                                            style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }}>
                                            <option value="latest_per_vm">Latest snapshot per VM</option>
                                            <option value="all">All snapshots in pool</option>
                                        </select>
                                    </label>
                                </div>
                                {err && <div style={{ color: '#f54f47', fontSize: '12px' }}>{err}</div>}
                                <div className="flex justify-end gap-2 pt-2" style={{ borderTop: '1px solid var(--corp-border, #29414e)' }}>
                                    <button onClick={onClose}
                                        className="px-3 py-1.5 text-sm"
                                        style={{ background: 'transparent', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)', borderRadius: '3px' }}>
                                        Cancel
                                    </button>
                                    <button onClick={save} disabled={busy}
                                        className="px-3 py-1.5 text-sm font-medium"
                                        style={{ background: 'var(--corp-accent, #0078a8)', color: '#fff', border: 'none', borderRadius: '3px',
                                                 opacity: busy ? 0.5 : 1 }}>
                                        {busy ? 'Saving…' : 'Save'}
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            );
        }
        try { window.PegaProxVerifyScheduleModal = VerifyScheduleModal; } catch (_) {}
