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
                    // LW Oct 2026 - a caption goes on the page of its picture, above it
                    const capLines = block.caption ? doc.splitTextToSize(block.caption, contentW) : [];
                    addPageIfNeeded(imgH + 4 + capLines.length * 4);
                    if (capLines.length) {
                        doc.setFont('helvetica', 'normal');
                        doc.setFontSize(9);
                        doc.setTextColor(60, 60, 60);
                        doc.text(capLines, margin, y + 4);
                        y += capLines.length * 4 + 2;
                    }
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

        // ═══════════════════════════════════════════════
        // REQUIRED LEGAL NOTICE — do not remove, hide, disable, obscure or alter.
        //
        // This line is part of this Program's "Appropriate Legal Notices" within the
        // meaning of AGPL-3.0 §0, and a required author attribution under §7(b); see the
        // NOTICE file at the repository root. It must remain visible, legible and
        // functional in every copy conveyed and in every instance made available to users
        // over a network (§13). The full notice — warranty disclaimer, redistribution
        // terms and the source offer — is in Settings → About, which the license link
        // below reaches.
        //
        // Deliberately not translated: it refers to an English-language license, and a
        // translated legal notice is a weaker one. NS Sep 2026
        // ═══════════════════════════════════════════════
        const LEGAL_REPO = 'https://github.com/PegaProx/project-pegaprox';
        const LEGAL_STRIP_H = 24;   // what a console window has to leave free for it

        function LegalNotice({ className = '', style = {} }) {
            const link = {color: 'inherit', textDecoration: 'underline', textUnderlineOffset: 2};
            return (
                <div id="pegaprox-legal-notice"
                     className={className}
                     style={{fontSize: 11, lineHeight: 1.6, textAlign: 'center',
                             padding: '6px 10px',
                             // body carries no colour of its own (everything here is Tailwind
                             // utility classes), so inheriting gives black — invisible on the
                             // dark skins. --color-text is themed but only defined per layout,
                             // and the login runs as "modern" whatever the instance default
                             // theme is; the literal is the modern-dark case.
                             color: 'var(--color-text, #cbd5e1)', opacity: 0.72, ...style}}>
                    {/* NBSP before each "·" so a wrap can never start a line with a stray
                        separator, and a normal space after it so the line CAN break there —
                        the 224px sidebar is the tight case. nowrap spans were the first
                        attempt and overflowed it (315px of content in 223px). */}
                    <a href="https://pegaprox.com" target="_blank" rel="noopener noreferrer"
                       style={link}>PegaProx</a>
                    {'\u00A0· © 2025-2026 PegaProx Team\u00A0· '}
                    <a href={`${LEGAL_REPO}/blob/main/LICENSE`} target="_blank"
                       rel="noopener noreferrer" style={link}>AGPL-3.0</a>
                    {'\u00A0· '}
                    <a href={LEGAL_REPO} target="_blank" rel="noopener noreferrer"
                       style={link}>Source</a>
                    {'\u00A0· '}
                    {/* The funding link sits INSIDE this element on purpose. Not because §7(b)
                        reaches it — it does not, and NOTICE deliberately keeps naming only the
                        four attribution elements above so the term stays narrow enough to hold.
                        It is here because this element is the one thing that renders on every
                        surface there is, which makes it the widest honest reach a
                        donation-funded project has. Removing just this link is lawful;
                        removing the element it lives in is not. */}
                    <a href="https://opencollective.com/pegaprox" target="_blank"
                       rel="noopener noreferrer" style={link}>Donate</a>
                </div>
            );
        }

        // LW Sep 2026 (#625) - where the active shows a console, shell or SPICE button, a
        // standby shows this: the same view on the active instance, in a new tab. A plain
        // link, so the address shows on hover and a middle click works as well. With a vm
        // it opens that guest's console window there, without one the start page. Nothing
        // on any other role, or while the address of the active is not known. button: for
        // a toolbar whose styles are written for buttons only.
        // A member that serves users opens its consoles itself and shows no link, except
        // the one next to a settings note (settings), which stays on every standby and
        // names the leader there.
        function HaOnActiveLink({ vm, clusterId, className = '', style, iconOnly = false, iconClass, button = false, settings = false }) {
            const { ha, haStandby, haConsolesElsewhere, haServing } = useAuth();
            const { t } = useTranslation();
            if (!(settings ? haStandby : haConsolesElsewhere)) return null;
            const href = haActiveHref(ha.peer_url, vm ? haConsoleSearch(vm, clusterId) : '');
            if (!href) return null;
            const label = haServing ? t('pgHaOpenOnLeader') : t('pgHaOpenOnActive');
            const inner = (
                <>
                    <Icons.ExternalLink className={iconClass} />
                    {!iconOnly && <span>{label}</span>}
                </>
            );
            if (button) {
                return (
                    <button type="button" onClick={() => window.open(href, '_blank', 'noopener,noreferrer')}
                        data-ha-on-active={href} className={className} style={style} title={label}
                        aria-label={iconOnly ? label : undefined}>
                        {inner}
                    </button>
                );
            }
            return (
                <a href={href} target="_blank" rel="noopener noreferrer" data-ha-on-active={href}
                    className={className} style={style} title={label} aria-label={iconOnly ? label : undefined}>
                    {inner}
                </a>
            );
        }

        // the node shell tabs and a console window opened on a standby: why there is no
        // terminal, and the way to the one on the active
        function HaConsoleOnActive({ vm, clusterId }) {
            const { t } = useTranslation();
            return (
                <div className="flex flex-col items-center justify-center gap-3 py-12 px-4 text-center" data-ha-console-elsewhere="">
                    <span className="text-gray-500"><Icons.Terminal /></span>
                    <p className="text-sm text-gray-400 max-w-md">{t('pgHaConsoleOnActive')}</p>
                    <HaOnActiveLink vm={vm} clusterId={clusterId}
                        className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium bg-proxmox-orange hover:bg-orange-600 text-white"
                        iconClass="w-4 h-4" />
                </div>
            );
        }

        // in place of a save button whose route no standby carries out, forwarding or not
        // (_STANDBY_NOT_FORWARDED in app.py). own: a form that holds this instance's own
        // settings (address, port, certificate...), which no sync brings either. A member
        // that serves users is no standby to them: the same note names the leader
        function HaSettingsOnActive({ own = false, className = '' }) {
            const { t } = useTranslation();
            const { haServing } = useAuth();
            const text = haServing ? (own ? t('pgHaOwnSettingsOnLeader') : t('pgHaSettingsOnLeader'))
                : (own ? t('pgHaOwnSettingsHere') : t('pgHaSettingsOnActive'));
            return (
                <div data-ha-settings-on-active={own ? 'own' : 'shared'}
                    className={`flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2 rounded-lg bg-yellow-500/10 border border-yellow-500/30 text-xs text-yellow-400 ${className}`}>
                    <span className="flex-1 min-w-0">{text}</span>
                    <HaOnActiveLink settings className="inline-flex items-center gap-1 font-medium text-proxmox-orange hover:underline" iconClass="w-3.5 h-3.5" />
                </div>
            );
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
            // LW Sep 2026 (#795) - shrink-0 belongs here, not at one call site: a fixed circle is
            // what an avatar IS, and as a flex child next to a long username it was being squeezed
            // to a sliver with the initials bleeding into the text.
            const classes = `${sizeClass} flex-shrink-0 rounded-full overflow-hidden flex items-center justify-center ${className}`.trim();

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
                    return d.length + ':' + d[0] + ':' + d[Math.floor(d.length/2)] + ':' + d[d.length-1];
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
                    // LW Oct 2026 - the time through fmtClock: browser time, and the 12h/24h
                    // setting the rest of the UI keeps (the locale's default ignored it)
                    for (let i = 0; i < timestamps.length; i++) {
                        const d = new Date(timestamps[i] * 1000);
                        if (useDateOnly) {
                            rawLabels.push(d.toLocaleDateString([], { month: 'short', day: 'numeric' }));
                        } else if (useDate) {
                            rawLabels.push(d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + fmtClock(d));
                        } else {
                            rawLabels.push(fmtClock(d));
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
                // LW Oct 2026 - a slot without a sample (null, undefined, NaN) stays null and
                // the line breaks there: it used to be drawn as a measured 0. A bucket of the
                // decimation takes its first real value, a sample between two gaps gets a dot
                chartDatasets.forEach(ds => {
                    if (!ds.data || ds.data.length === 0) return;
                    const cleanData = [];
                    for (let i = 0; i < ds.data.length; i++) {
                        const v = ds.data[i];
                        cleanData.push((typeof v === 'number' && isFinite(v)) ? v : null);
                    }

                    let finalData = [];
                    if (step > 1) {
                        for (let i = 0; i < cleanData.length; i += step) {
                            let v = null;
                            for (let j = i; j < Math.min(i + step, cleanData.length) && v === null; j++) v = cleanData[j];
                            finalData.push(v);
                        }
                    } else {
                        finalData = cleanData;
                    }
                    const lone = finalData.map((v, i) => v !== null && (i === 0 || finalData[i - 1] === null) && (i === finalData.length - 1 || finalData[i + 1] === null));

                    processedDatasets.push({
                        label: ds.label || label,
                        data: finalData,
                        borderColor: ds.color || color,
                        backgroundColor: (ds.color || color) + '33',
                        fill: ds.fill !== undefined ? ds.fill : true,
                        spanGaps: false,
                        tension: 0.4,
                        pointRadius: lone.some(Boolean) ? (c => lone[c.dataIndex] ? 2 : 0) : 0,
                        pointBackgroundColor: ds.color || color,
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
                                            if (val === null || val === undefined || val !== val) return ' ' + c.dataset.label + ': -';
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
                return data.metrics.memory.map(p => p === null ? null : (p / 100) * maxMemGB);
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
                        { text: `Getting join info from ${clusterLabel(targetCluster)}...`, status: 'running' }
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
                        { text: `Got join info from ${clusterLabel(targetCluster)}`, status: 'done' },
                        { text: `Joining node to ${clusterLabel(targetCluster)}...`, status: 'running' }
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
                            { text: `Successfully joined ${clusterLabel(targetCluster)}!`, status: 'done' }
                        ]);
                        if (addToast) addToast(`Node ${nodeName} moved to ${clusterLabel(targetCluster)}`, 'success');
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
                                                        {clusterLabel(c)}
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

        // LW Oct 2026 - API reference from the user menu. Renders the OpenAPI document the
        // server builds from its own route table (GET /api/pegaprox/openapi.json). Read-only
        // on purpose: nothing in here sends a request to the routes it lists.
        const API_REF_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
        const API_REF_METHOD_CLS = {
            GET: 'text-blue-400 border-blue-500/50',
            POST: 'text-green-400 border-green-500/50',
            PUT: 'text-yellow-400 border-yellow-500/50',
            PATCH: 'text-purple-400 border-purple-500/50',
            DELETE: 'text-red-400 border-red-500/50',
        };
        // fetched once per page load, an update reloads the page anyway
        let apiRefDoc = null;

        function apiRefOperations(doc) {
            const out = [];
            Object.entries((doc && doc.paths) || {}).forEach(([path, methods]) => {
                Object.entries(methods || {}).forEach(([method, op]) => {
                    if (!op || typeof op !== 'object') return;
                    const m = method.toUpperCase();
                    const tag = (op.tags && op.tags[0]) || '';
                    const perms = op['x-pegaprox-permissions'] || [];
                    const roles = op['x-pegaprox-roles'] || [];
                    // a URL pasted from the browser finds its route: {cluster_id} stands for one segment
                    const shape = new RegExp('^' + path.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{[^}/]+\}/g, '[^/]+') + '/?$', 'i');
                    out.push({
                        key: `${m} ${path}`, method: m, path, tag, shape, perms, roles,
                        summary: op.summary || '', description: op.description || '',
                        auth: op['x-pegaprox-auth'] || '', security: op.security,
                        params: op.parameters || [], body: !!op.requestBody,
                        responses: Object.keys(op.responses || {}), operationId: op.operationId || '',
                        shadowed: op['x-pegaprox-shadowed-by'] || [],
                        text: [m, path, op.summary, op.description, tag, op.operationId, ...perms, ...roles].join(' ').toLowerCase(),
                    });
                });
            });
            const rank = (m) => { const i = API_REF_METHODS.indexOf(m); return i < 0 ? 99 : i; };
            out.sort((a, b) => a.tag.localeCompare(b.tag) || a.path.localeCompare(b.path) || rank(a.method) - rank(b.method));
            return out;
        }

        // Words match anywhere. A word starting with / is a path (a full URL works too), and
        // next to one a method name is the method: "POST /api/clusters/c1/updates/rolling"
        // as a log line has it. A path that names a route exactly shows that route only.
        function apiRefMatcher(query) {
            const words = String(query || '').trim().split(/\s+/).filter(Boolean).map(w => {
                const url = w.match(/^https?:\/\/[^/]+(\/.*)?$/i);
                return url ? (url[1] || '/') : w;
            });
            if (!words.length) return null;
            const paths = words.filter(w => w.startsWith('/')).map(w => w.split(/[?#]/)[0].toLowerCase());
            const methods = paths.length ? words.map(w => w.toUpperCase()).filter(w => API_REF_METHODS.includes(w)) : [];
            const rest = words.filter(w => !w.startsWith('/') && !methods.includes(w.toUpperCase())).map(w => w.toLowerCase());
            const base = (op) => (!methods.length || methods.includes(op.method)) && rest.every(w => op.text.includes(w));
            return {
                paths: paths.length > 0,
                exact: (op) => base(op) && paths.every(p => op.shape.test(p)),
                loose: (op) => base(op) && paths.every(p => op.shape.test(p) || op.path.toLowerCase().includes(p)),
            };
        }

        function ApiReferenceModal({ onClose }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const { isCorporate } = useLayout();
            const [doc, setDoc] = useState(apiRefDoc);
            const [failed, setFailed] = useState(false);
            const [query, setQuery] = useState('');
            const [method, setMethod] = useState('');
            const [area, setArea] = useState('');
            const [open, setOpen] = useState({});
            const searchRef = useRef(null);

            const load = useCallback(async () => {
                setFailed(false);
                try {
                    const r = await fetch(`${API_URL}/pegaprox/openapi.json`, { credentials: 'include', headers: getAuthHeaders() });
                    if (!r.ok) throw new Error(String(r.status));
                    const body = await r.json();
                    if (!body || typeof body.paths !== 'object') throw new Error('no paths');
                    apiRefDoc = body;
                    setDoc(body);
                } catch (e) {
                    setFailed(true);
                }
            }, [getAuthHeaders]);

            useEffect(() => { if (!apiRefDoc) load(); }, [load]);
            useEffect(() => {
                // capture: "/" is the search of the page behind otherwise
                const onKey = (e) => {
                    if (e.key === 'Escape') { e.preventDefault(); onClose(); return; }
                    const el = e.target;
                    const typing = el && (['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName) || el.isContentEditable);
                    if (e.key === '/' && !typing && searchRef.current) {
                        e.preventDefault();
                        e.stopPropagation();
                        searchRef.current.focus();
                    }
                };
                window.addEventListener('keydown', onKey, true);
                return () => window.removeEventListener('keydown', onKey, true);
            }, [onClose]);
            useEffect(() => { if (doc && searchRef.current) searchRef.current.focus(); }, [doc]);

            const ops = useMemo(() => apiRefOperations(doc), [doc]);
            // the field keeps up with the keyboard, the 900-odd rows follow when React has time
            const typed = React.useDeferredValue(query);
            // search and method first: the area list counts what they leave
            const hits = useMemo(() => {
                const match = apiRefMatcher(typed);
                const pool = method ? ops.filter(op => op.method === method) : ops;
                if (!match) return pool;
                const exact = match.paths ? pool.filter(match.exact) : [];
                return exact.length ? exact : pool.filter(match.loose);
            }, [ops, typed, method]);
            const areas = useMemo(() => {
                const all = {}, hit = {};
                ops.forEach(op => { all[op.tag] = 0; });
                hits.forEach(op => { hit[op.tag] = (hit[op.tag] || 0) + 1; });
                return Object.keys(all).sort().map(tag => [tag, hit[tag] || 0]);
            }, [ops, hits]);
            const shown = area ? hits.filter(op => op.tag === area) : hits;

            const toggle = (key) => setOpen(o => ({ ...o, [key]: !o[key] }));
            const chip = 'text-[11px] px-1.5 py-0.5 rounded border';

            const who = (op) => {
                const needs = [
                    ...op.roles.map(r => <span key={`role:${r}`} className={`${chip} bg-proxmox-dark border-proxmox-border text-gray-300`}>{t('apiRefRole').replace('{role}', r)}</span>),
                    ...op.perms.map(p => <span key={p} className={`${chip} font-mono bg-proxmox-dark border-proxmox-border text-gray-300`}>{p}</span>),
                ];
                if (needs.length) return needs;
                if (op.auth === 'public') return <span className={`${chip} text-green-400 border-green-500/50`}>{t('apiRefPublic')}</span>;
                if (op.auth === 'inline') return <span className={`${chip} text-gray-400 border-proxmox-border`}>{t('apiRefOwnAuth')}</span>;
                return <span className={`${chip} text-gray-400 border-proxmox-border`}>{t('apiRefSignedIn')}</span>;
            };

            // the securitySchemes of gen_openapi.py
            const scheme = (name) => {
                switch (name) {
                    case 'apiToken': return t('apiRefSchemeApi');
                    case 'sessionId': return t('apiRefSchemeSession');
                    case 'installToken': return t('apiRefSchemeInstall');
                    case 'haPeer': return t('apiRefSchemePeer');
                    default: return name;
                }
            };
            const schemes = (op) => {
                if (!Array.isArray(op.security)) return t('apiRefPublic');
                if (!op.security.length) return t('apiRefSchemeCode');
                return op.security.map(req => {
                    const names = Object.keys(req || {});
                    return names.length ? names.map(scheme).join(' + ') : t('apiRefSchemeCode');
                }).join(' / ');
            };

            const detail = (op) => (
                <div data-api-detail={op.key} className="px-4 pb-4 pt-1 space-y-3 text-sm">
                    {op.summary && <div className="font-medium">{op.summary}</div>}
                    {op.description
                        ? <div className="text-xs text-gray-400 whitespace-pre-wrap">{op.description}</div>
                        : !op.summary && <div className="text-xs text-gray-500">{t('apiRefNoDescription')}</div>}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <div className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-1">{t('apiRefAuth')}</div>
                            <div className="text-xs text-gray-300">{schemes(op)}</div>
                            <div className="flex flex-wrap gap-1 mt-1.5">{who(op)}</div>
                        </div>
                        <div>
                            <div className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-1">{t('apiRefResponses')}</div>
                            <div className="flex flex-wrap gap-1">
                                {op.responses.map(code => <span key={code} className={`${chip} font-mono bg-proxmox-dark border-proxmox-border text-gray-300`}>{code}</span>)}
                            </div>
                        </div>
                    </div>
                    {op.params.length > 0 && (
                        <div>
                            <div className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-1">{t('apiRefParameters')}</div>
                            <div className="space-y-1">
                                {op.params.map(p => (
                                    <div key={`${p.in}:${p.name}`} className="flex flex-wrap items-center gap-2 text-xs">
                                        <span className="font-mono text-gray-200">{p.name}</span>
                                        <span className="text-gray-500">{p.in}</span>
                                        <span className="font-mono text-gray-400">{[p.schema && p.schema.type, p.schema && p.schema.format].filter(Boolean).join(' / ')}</span>
                                        {p.required && <span className="text-yellow-400">{t('apiRefRequired')}</span>}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    {op.body && <div className="text-xs text-gray-400">{t('apiRefBody')}</div>}
                    {op.shadowed.length > 0 && (
                        <div className="text-xs text-yellow-400">{t('apiRefShadowed').replace('{endpoints}', op.shadowed.join(', '))}</div>
                    )}
                    <div className="flex flex-wrap items-center gap-2 text-xs text-gray-500">
                        <span>{t('apiRefOperationId')}:</span>
                        <span className="font-mono text-gray-400 break-all">{op.operationId}</span>
                        <CopyButton value={op.path} title={t('apiRefCopyPath')} />
                    </div>
                </div>
            );

            const rows = [];
            shown.forEach((op, i) => {
                if (!area && (i === 0 || shown[i - 1].tag !== op.tag)) {
                    rows.push(
                        <div key={`area:${op.tag}`} data-api-area={op.tag} className="px-4 pt-4 pb-1 text-xs font-semibold uppercase tracking-wider text-gray-500">{op.tag}</div>
                    );
                }
                const isOpen = !!open[op.key];
                rows.push(
                    <div key={op.key} data-api-op={op.key} className="border-t border-proxmox-border">
                        <button type="button" onClick={() => toggle(op.key)} aria-expanded={isOpen}
                            className={`w-full flex items-center gap-3 px-4 ${isCorporate ? 'py-1.5' : 'py-2'} text-left hover:bg-proxmox-hover transition-colors`}>
                            <Icons.ChevronRight className={`w-3 h-3 flex-shrink-0 text-gray-500 transition-transform ${isOpen ? 'rotate-90' : ''}`} />
                            <span className={`w-16 flex-shrink-0 text-center text-[11px] font-bold font-mono py-0.5 rounded border ${API_REF_METHOD_CLS[op.method] || 'text-gray-400 border-proxmox-border'}`}>{op.method}</span>
                            <span className="font-mono text-sm break-all">{op.path}</span>
                            <span className="flex-1 min-w-0 truncate text-xs text-gray-400">{op.summary}</span>
                            <span className="ml-auto flex flex-wrap justify-end gap-1 flex-shrink-0">{who(op)}</span>
                        </button>
                        {isOpen && detail(op)}
                    </div>
                );
            });

            const version = doc && doc.info && doc.info.version;
            // no bg-proxmox-orange on a button here: Corporate paints those as primary buttons
            const areaBtn = (active) => `w-full flex items-center justify-between gap-2 px-3 py-1.5 text-left text-xs rounded transition-colors ${active ? 'bg-proxmox-dark text-proxmox-orange font-medium' : 'text-gray-300 hover:bg-proxmox-hover'}`;
            return (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
                    <div data-api-reference="" className="bg-proxmox-card border border-proxmox-border rounded-xl w-full max-w-6xl shadow-2xl flex flex-col" style={{ height: '88vh', color: 'var(--color-text, #e9ecef)' }} onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-between gap-3 px-6 py-4 border-b border-proxmox-border">
                            <div className="flex items-center gap-2 min-w-0">
                                <span className="text-proxmox-orange flex-shrink-0"><Icons.Book /></span>
                                <h3 className="text-lg font-semibold truncate">{t('apiRefTitle')}</h3>
                                {version && <span className="text-xs font-mono px-2 py-0.5 rounded bg-proxmox-dark border border-proxmox-border text-gray-400">v{version}</span>}
                            </div>
                            <div className="flex items-center gap-2">
                                {doc && (
                                    <button type="button" onClick={() => downloadJson(`pegaprox-openapi-${version || 'current'}.json`, doc)}
                                        className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm bg-proxmox-dark border border-proxmox-border hover:border-proxmox-orange/50 transition-colors">
                                        <Icons.Download />
                                        <span className="hidden sm:inline">{t('apiRefDownload')}</span>
                                    </button>
                                )}
                                <button type="button" onClick={onClose} className="text-gray-400 hover:text-white p-1" title={t('close')}><Icons.X /></button>
                            </div>
                        </div>
                        {!doc ? (
                            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-sm text-gray-400">
                                {failed ? (
                                    <>
                                        <span className="text-red-400">{t('apiRefLoadFailed')}</span>
                                        <button type="button" onClick={load} className="px-4 py-2 rounded-lg text-sm font-medium bg-proxmox-orange hover:bg-orange-600 text-white">{t('apiRefRetry')}</button>
                                    </>
                                ) : (
                                    <span className="flex items-center gap-2"><span className="animate-spin inline-flex"><Icons.Loader /></span>{t('apiRefLoading')}</span>
                                )}
                            </div>
                        ) : (
                            <>
                                <div className="px-6 py-3 space-y-3 border-b border-proxmox-border">
                                    <p className="text-xs text-gray-400">{t('apiRefIntro')}</p>
                                    <div className="flex flex-wrap items-center gap-3">
                                        <div className="flex items-center gap-2 flex-1 min-w-0" style={{ minWidth: '16rem' }}>
                                            <Icons.Search className="w-4 h-4 text-gray-500 flex-shrink-0" />
                                            <input ref={searchRef} type="search" value={query} onChange={e => setQuery(e.target.value)}
                                                placeholder={t('apiRefSearch')} aria-label={t('apiRefSearch')}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm focus:outline-none focus:border-proxmox-orange" />
                                        </div>
                                        <div className="flex items-center gap-1">
                                            {['', ...API_REF_METHODS].map(m => (
                                                <button key={m || 'all'} type="button" onClick={() => setMethod(m)} data-api-method={m || 'all'}
                                                    className={`px-2 py-1 rounded text-xs font-mono border transition-colors ${method === m ? 'border-proxmox-orange text-proxmox-orange' : 'border-proxmox-border text-gray-400 hover:text-white'}`}>
                                                    {m || t('apiRefAllMethods')}
                                                </button>
                                            ))}
                                        </div>
                                        <span data-api-count="" className="text-xs text-gray-500 whitespace-nowrap">
                                            {t('apiRefCount').replace('{shown}', String(shown.length)).replace('{total}', String(ops.length))}
                                        </span>
                                    </div>
                                </div>
                                <div className="flex flex-1" style={{ minHeight: 0 }}>
                                    {/* sm:inline on a flex item still lays out as a block */}
                                    <div className="hidden sm:inline w-56 flex-shrink-0 overflow-y-auto border-r border-proxmox-border p-2 space-y-0.5">
                                        <button type="button" onClick={() => setArea('')} className={areaBtn(!area)}>
                                            <span>{t('apiRefAllAreas')}</span><span className="text-gray-500">{hits.length}</span>
                                        </button>
                                        {areas.map(([tag, n]) => (
                                            <button key={tag} type="button" data-api-area-pick={tag} onClick={() => setArea(area === tag ? '' : tag)}
                                                className={`${areaBtn(area === tag)} ${n ? '' : 'opacity-50'}`}>
                                                <span className="font-mono truncate">{tag}</span><span className="text-gray-500">{n}</span>
                                            </button>
                                        ))}
                                    </div>
                                    <div className="flex-1 min-w-0 overflow-y-auto pb-4">
                                        {/* on a phone a select takes the place of the area list */}
                                        <div className="sm:hidden px-4 pt-3">
                                            <select value={area} onChange={e => setArea(e.target.value)} aria-label={t('apiRefAllAreas')}
                                                className="w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm">
                                                <option value="">{t('apiRefAllAreas')}</option>
                                                {areas.map(([tag, n]) => <option key={tag} value={tag}>{tag} ({n})</option>)}
                                            </select>
                                        </div>
                                        {rows.length ? rows : <div className="px-4 py-12 text-center text-sm text-gray-500">{t('apiRefNoMatch')}</div>}
                                    </div>
                                </div>
                            </>
                        )}
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

        // LW Oct 2026 - the guest inventory as CSV, of one cluster or (no clusterId) of every
        // cluster the user reaches. GET /inventory/guests leaves out each guest they may not see.
        // Headers stay English so a script reading the file does not break on the language.
        function inventoryCsvColumns(clusterLabel) {
            const mib = (b) => b != null ? Math.round(b / 1048576) : '';
            // 0 is a size too: an empty disk reads 0.0, not a blank cell
            const gib = (b) => b != null ? (b / 1073741824).toFixed(1) : '';
            return [
                { key: 'cluster', label: 'Cluster', map: clusterLabel },
                { key: 'vmid', label: 'VMID' },
                { key: 'name', label: 'Name' },
                { key: 'type', label: 'Type' },
                { key: 'node', label: 'Node' },
                { key: 'status', label: 'Status' },
                { key: 'template', label: 'Template', map: g => g.template ? 'yes' : '' },
                { key: 'vcpus', label: 'vCPU', map: g => g.vcpus || '' },
                { key: 'cpu', label: 'CPU%', map: g => g.cpu != null ? Math.round(g.cpu * 100) : '' },
                { key: 'mem', label: 'Mem (MiB)', map: g => mib(g.mem) },
                { key: 'memory', label: 'MemMax (MiB)', map: g => mib(g.memory) },
                { key: 'disk_allocated', label: 'Disk allocated (GiB)', map: g => gib(g.disk_allocated) },
                { key: 'disk_used', label: 'Disk used (GiB)', map: g => gib(g.disk_used) },
                { key: 'ip_addresses', label: 'IP addresses', map: g => (g.ip_addresses || []).join(' ') },
                { key: 'ha_state', label: 'HA state' },
                { key: 'pool', label: 'Pool' },
                { key: 'tags', label: 'Tags', map: g => (g.tags || []).join(';') },
            ];
        }

        function InventoryCsvButton({ clusterId, clusters, fileName, addToast, className, label }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [busy, setBusy] = useState(false);
            const run = async () => {
                if (busy) return;
                setBusy(true);
                try {
                    const q = clusterId ? `?cluster=${encodeURIComponent(clusterId)}` : '';
                    const r = await fetch(`${API_URL}/inventory/guests${q}`, { headers: getAuthHeaders() });
                    if (!r.ok) { addToast?.(t('inventoryCsvFailed'), 'error'); return; }
                    const data = await r.json();
                    const rows = data.guests || [];
                    const clusterLabel = (g) => {
                        const c = (clusters || []).find(x => x.id === g.cluster_id);
                        return (c && (c.display_name || c.name)) || g.cluster_name;
                    };
                    const missing = (data.clusters || []).filter(c => c.state !== 'ok').map(clusterLabel);
                    if (missing.length) addToast?.(t('inventoryCsvMissing').replace('{clusters}', missing.join(', ')), 'warning');
                    if (!rows.length) { addToast?.(t('inventoryCsvEmpty'), 'info'); return; }
                    const fname = fileName || `pegaprox-inventory-${new Date().toISOString().slice(0, 10)}.csv`;
                    downloadCsv(fname, rows, inventoryCsvColumns(clusterLabel));
                    addToast?.(t('inventoryCsvExported').replace('{n}', rows.length), 'success');
                } catch (e) {
                    console.error('inventory export:', e);
                    addToast?.(t('inventoryCsvFailed'), 'error');
                } finally {
                    setBusy(false);
                }
            };
            return (
                <button type="button" data-inventory-csv={clusterId || 'all'} onClick={run} disabled={busy}
                    className={className} title={t('inventoryCsvTitle')}>
                    <span className={`inline-flex ${busy ? 'animate-pulse' : ''}`}><Icons.Download /></span>
                    {label}
                </button>
            );
        }

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
            const { t } = useTranslation();
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
                        title={t('pbsHealthTooltip') || 'PBS health — click for breakdown'}
                    >
                        <span style={{ fontWeight: 700 }}>{data.score}</span>
                        <span style={{ opacity: 0.75, fontSize: '0.7rem' }}>{t('pbsHealthLabel') || 'health'}</span>
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
            const { t } = useTranslation();
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
                            // LW Oct 2026 - the route answers {log, lines}; this read an array that never came
                            let arr = Array.isArray(data) ? data
                                : Array.isArray(data.lines) ? data.lines
                                : (data.data || []);
                            // Proxmox answers an empty log with one 'no content' line
                            if (arr.length === 1 && arr[0] === 'no content') arr = [];
                            if (arr.length) {
                                if (cancelled) return;
                                setLines(prev => [...prev, ...arr.map(l => (l && l.t !== undefined) ? l.t : l)]);
                                startLine += arr.length;
                                // throughput sniff: look for "INFO: ... read X.X GiB/s" or "transferred"
                                const recent = arr.map(l => (l && l.t !== undefined) ? l.t : l).join('\n');
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
                            <span className="font-medium text-sm">{done ? (exitstatus === 'OK' ? (t('pbsBackupCompleted') || 'Backup completed') : `${t('pbsBackupFailed') || 'Backup failed'} (${exitstatus})`) : (t('pbsBackupInProgress') || 'Backup in progress…')}</span>
                            {throughput.length > 0 && (
                                <span className="text-xs opacity-70" style={{ fontVariantNumeric: 'tabular-nums' }}>
                                    {throughput[throughput.length - 1].mbps.toFixed(1)} MiB/s · {t('pbsPeak') || 'peak'} {peakMbps.toFixed(1)}
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
                        {lines.length === 0 ? <span className="opacity-50">{t('pbsWaitingForOutput') || 'Waiting for output…'}</span>
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
            const { t } = useTranslation();
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
                    <div className="text-xs uppercase tracking-wide opacity-70 mb-2">{t('capacityForecast') || 'Capacity forecast'}</div>
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
            const { t } = useTranslation();
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
                        <span className="opacity-80">{t('preflightCheck') || 'Pre-flight check (PBS)'}</span>
                        <button onClick={run} disabled={state.status === 'checking'}
                            style={{ background: 'var(--corp-accent, #0078a8)', color: '#fff', padding: '2px 8px',
                                     borderRadius: '3px', border: 'none', cursor: 'pointer',
                                     opacity: state.status === 'checking' ? 0.5 : 1 }}>
                            {state.status === 'checking' ? (t('pbsCheckingEllipsis') || 'Checking…') : (t('runCheck') || 'Run check')}
                        </button>
                    </div>
                    {state.status === 'ok' && <div style={{ color: '#60b515', marginTop: '4px' }}>✓ {t('pbsAllChecksPassed') || 'All checks passed. Live fingerprint matches; auth ok; datastore exists.'}</div>}
                    {state.status === 'fail' && (
                        <ul style={{ marginTop: '4px', paddingLeft: '18px' }}>
                            {state.issues.map((iss, i) => <li key={i} style={{ color: '#f54f47' }}>{iss}</li>)}
                        </ul>
                    )}
                    {state.info.live_fingerprint && state.status !== 'ok' && (
                        <div style={{ marginTop: '4px', opacity: 0.7, fontFamily: 'ui-monospace, monospace', fontSize: '11px', wordBreak: 'break-all' }}>
                            {t('liveFingerprint') || 'Live fingerprint'}: {state.info.live_fingerprint}
                        </div>
                    )}
                </div>
            );
        }
        try { window.PegaProxStoragePreflightCheck = StoragePreflightCheck; } catch (_) {}

        // Auto-Fingerprint button — fetches the cert fingerprint via probe endpoint
        function FingerprintFetcher({ host, port, authFetch, apiUrl, onFetched }) {
            const { t } = useTranslation();
            const [busy, setBusy] = React.useState(false);
            const [error, setError] = React.useState(null);
            const fetchIt = async () => {
                if (!host) { setError(t('pbsHostRequired') || 'host required'); return; }
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
                        title={t('pbsCaptureTlsFingerprint') || 'Connect to host and capture the TLS fingerprint'}>
                        {busy ? '…' : (t('autoFetch') || 'Auto-fetch')}
                    </button>
                    {error && <span style={{ color: '#f54f47', fontSize: '11px' }}>{error}</span>}
                </span>
            );
        }
        try { window.PegaProxFingerprintFetcher = FingerprintFetcher; } catch (_) {}

        // Backup Restore Wizard — three-mode (new/overwrite/test)
        function BackupRestoreWizard({ clusterId, snapshot, datastoreName, nodes, storages, authFetch, apiUrl, onClose, onStarted }) {
            const { t } = useTranslation();
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
                new: t('pbsRestoreNewDesc') || 'Restore as a new VM with the chosen VMID. Original VM stays untouched.',
                overwrite: t('pbsRestoreOverwriteDesc') || 'Overwrite an existing VM with the same VMID. Existing config + disks will be lost.',
                test: t('pbsRestoreTestDesc') || 'Test-restore — restore + boot, then keep the test VM (no auto-cleanup). Useful for DR drills.',
            };

            return (
                <div className="fixed inset-0 z-[10010] flex items-center justify-center p-4" style={{ background: 'rgba(8,14,24,0.72)' }} onClick={onClose}>
                    <div
                        className="rounded-lg shadow-2xl w-full max-w-lg"
                        style={{ background: 'var(--corp-surface, #1c2733)', color: 'var(--corp-text, #e9ecef)', border: '1px solid var(--corp-border, #29414e)' }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="px-5 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--corp-border, #29414e)' }}>
                            <div className="text-base font-semibold">{t('pbsRestoreBackup') || 'Restore backup'}</div>
                            <button onClick={onClose} className="opacity-60 hover:opacity-100 leading-none" style={{fontSize:'18px'}}>×</button>
                        </div>
                        <div className="p-5 space-y-3">
                            <div className="text-xs opacity-70">{t('pbsRestoreSource') || 'Source'}: {snapshot?.volid || (t('pbsUnknown') || '(unknown)')}</div>

                            <div>
                                <div className="text-xs uppercase tracking-wide opacity-60 mb-1">{t('pbsRestoreMode') || 'Mode'}</div>
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
                                <div className="text-xs uppercase tracking-wide opacity-60 mb-1">{t('pbsTargetNode') || 'Target node'}</div>
                                <select value={targetNode} onChange={e => setTargetNode(e.target.value)}
                                    className="w-full px-2 py-1.5 text-sm"
                                    style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }}>
                                    {(nodes || []).map(n => <option key={n} value={n}>{n}</option>)}
                                </select>
                            </div>

                            <div>
                                <div className="text-xs uppercase tracking-wide opacity-60 mb-1">{t('pbsTargetVmid') || 'Target VMID'}</div>
                                <input type="number" value={targetVmid} onChange={e => setTargetVmid(e.target.value)}
                                    className="w-full px-2 py-1.5 text-sm"
                                    style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }} />
                            </div>

                            <div>
                                <div className="text-xs uppercase tracking-wide opacity-60 mb-1">{t('pbsTargetStorageOptional') || 'Target storage (optional)'}</div>
                                <select value={targetStorage} onChange={e => setTargetStorage(e.target.value)}
                                    className="w-full px-2 py-1.5 text-sm"
                                    style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }}>
                                    <option value="">{t('pbsUseBackupDefault') || '— use default from backup —'}</option>
                                    {(storages || []).map(s => <option key={s} value={s}>{s}</option>)}
                                </select>
                            </div>

                            {error && <div style={{ color: '#f54f47', fontSize: '12px' }}>{error}</div>}

                            <div className="flex justify-end gap-2 pt-2" style={{ borderTop: '1px solid var(--corp-border, #29414e)' }}>
                                <button type="button" onClick={onClose}
                                    className="px-3 py-1.5 text-sm"
                                    style={{ background: 'transparent', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)', borderRadius: '3px' }}>
                                    {t('cancel') || 'Cancel'}
                                </button>
                                <button type="button" onClick={submit} disabled={running || !targetNode || !targetVmid}
                                    className="px-3 py-1.5 text-sm font-medium"
                                    style={{ background: mode === 'overwrite' ? '#b94a3a' : 'var(--corp-accent, #0078a8)',
                                             color: '#fff', border: 'none', borderRadius: '3px',
                                             opacity: (running || !targetNode || !targetVmid) ? 0.5 : 1 }}>
                                    {running ? (t('pbsStartingEllipsis') || 'Starting…') : `${t('pbsStartRestore') || 'Start restore'} (${mode})`}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            );
        }
        try { window.PegaProxBackupRestoreWizard = BackupRestoreWizard; } catch (_) {}

        // LW Oct 2026 - what the runs of a backup job did, and several backups restored in one
        // go. Both dialogs are wider than the bulk ones and follow the layout the same way.
        const bkpFill = (s, vars) => String(s || '').replace(/\{(\w+)\}/g, (m, k) => (vars && vars[k] != null ? String(vars[k]) : m));
        const bkpWhen = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '-');
        function bkpTook(sec) {
            if (sec == null) return '-';
            const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
            return h ? `${h}h ${m}m` : m ? `${m}m ${s}s` : `${s}s`;
        }
        async function bkpError(res, t, haServing) {
            if (!res) return t('actionFailed');
            const body = await res.clone().json().catch(() => null);
            if (body && body.code === 'HA_STANDBY') return haServing ? t('pgHaServingRefused') : t('pgHaStandbyRefused');
            if (body && body.code === 'HA_ACTIVE_UNREACHABLE') return haServing ? t('pgHaLeaderUnreachable') : t('pgHaActiveUnreachable');
            return (body && typeof body.error === 'string' && body.error) || `${t('actionFailed')} (HTTP ${res.status})`;
        }
        const BKP_STATE_CLS = {
            ok: 'text-green-400', done: 'text-green-400', warning: 'text-yellow-400', failed: 'text-red-400',
            running: 'text-blue-400', restoring: 'text-blue-400', wait: 'text-gray-400', skipped: 'text-yellow-400',
            cancelled: 'text-gray-400', unknown: 'text-yellow-400',
        };

        function BackupFrame({ icon, title, meta, onClose, footer, children, testId }) {
            const { t } = useTranslation();
            const { isCorporate } = useLayout();
            if (isCorporate) {
                return (
                    <div className="corp-vm-modal-overlay" onClick={onClose}>
                        <div className="corp-vm-modal" data-testid={testId} role="dialog" aria-modal="true"
                            style={{ maxWidth: '920px', width: '100%', alignSelf: 'center', maxHeight: '90vh' }}
                            onClick={e => e.stopPropagation()}>
                            <div className="corp-vm-modal-header">
                                <div className="flex items-center gap-3 min-w-0 flex-1">
                                    <span className="flex flex-shrink-0" style={{ color: 'var(--corp-accent, #49afd9)' }}>{icon}</span>
                                    <div className="min-w-0">
                                        <div className="corp-vm-modal-title truncate">{title}</div>
                                        {meta && <div className="corp-vm-modal-meta">{meta}</div>}
                                    </div>
                                </div>
                                <div className="corp-vm-modal-actions">
                                    <button onClick={onClose} className="corp-vm-btn corp-vm-btn-ghost" title={t('close')}><Icons.X /></button>
                                </div>
                            </div>
                            <div className="corp-vm-modal-body">{children}</div>
                            {footer && <div className="corp-vm-modal-footer"><div className="flex items-center gap-2 ml-auto">{footer}</div></div>}
                        </div>
                    </div>
                );
            }
            return (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80" onClick={onClose}>
                    <div className="w-full max-w-4xl max-h-[90vh] flex flex-col bg-proxmox-card border border-proxmox-border rounded-xl animate-scale-in"
                        data-testid={testId} role="dialog" aria-modal="true" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center gap-3 p-5 border-b border-proxmox-border">
                            <span className="flex flex-shrink-0 text-proxmox-orange">{icon}</span>
                            <div className="min-w-0 flex-1">
                                <h3 className="text-lg font-semibold text-white truncate">{title}</h3>
                                {meta && <div className="text-xs text-gray-400">{meta}</div>}
                            </div>
                            <button onClick={onClose} className="p-1 text-gray-400 hover:text-white rounded" title={t('close')}><Icons.X /></button>
                        </div>
                        <div className="p-5 space-y-4 overflow-y-auto">{children}</div>
                        {footer && <div className="flex justify-end gap-3 p-4 border-t border-proxmox-border">{footer}</div>}
                    </div>
                </div>
            );
        }

        // the runs come from the vzdump tasks of the nodes, the guests of a run from its task
        // logs and only once it is opened, the log of a guest only once that is opened
        const BKP_GUEST_PAGE = 100;
        const BKP_TASKS_PER_READ = 16;

        function BackupJobRunsModal({ clusterId, job, onClose }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const { isCorporate } = useLayout();
            const [days, setDays] = useState(14);
            const [data, setData] = useState(null);
            const [loading, setLoading] = useState(true);
            const [error, setError] = useState('');
            const [open, setOpen] = useState(null);
            const [guests, setGuests] = useState({});
            const [logs, setLogs] = useState({});
            const [shown, setShown] = useState(BKP_GUEST_PAGE);
            const [onlyFailed, setOnlyFailed] = useState(false);
            const headers = useRef(getAuthHeaders);
            headers.current = getAuthHeaders;
            const base = `${API_URL}/clusters/${encodeURIComponent(clusterId)}/datacenter/backup/${encodeURIComponent(job.id)}/runs`;
            const get = (url) => fetch(url, { credentials: 'include', headers: headers.current() });
            // only the newest look may answer: a slow one for the period before must not land
            const look = useRef(0);

            const load = useCallback(async () => {
                const mine = ++look.current;
                setLoading(true);
                setError('');
                try {
                    const res = await get(`${base}?days=${days}`);
                    if (mine !== look.current) return;
                    if (res.ok) setData(await res.json());
                    else { setData(null); setError(await PegaProxApiErrors.message(res, t('bkpRunsLoadFailed'))); }
                } catch (e) {
                    if (mine === look.current) setError(t('bkpRunsLoadFailed'));
                }
                if (mine === look.current) setLoading(false);
            }, [base, days]);  // eslint-disable-line react-hooks/exhaustive-deps
            useEffect(() => { load(); }, [load]);

            const openRun = async (run) => {
                if (open === run.id) { setOpen(null); return; }
                setOpen(run.id);
                setShown(BKP_GUEST_PAGE);
                const had = guests[run.id];
                if (had && had.data && run.state !== 'running') return;
                setGuests(g => ({ ...g, [run.id]: { loading: true } }));
                // a few tasks per read keeps the address short on a cluster of many nodes
                const merged = { guests: [], tasks: [], missing: null };
                let failed = '';
                for (let i = 0; i < run.tasks.length; i += BKP_TASKS_PER_READ) {
                    const qs = run.tasks.slice(i, i + BKP_TASKS_PER_READ).map(x => 'upid=' + encodeURIComponent(x.upid)).join('&');
                    try {
                        const res = await get(`${base}/guests?${qs}`);
                        if (!res.ok) { failed = await PegaProxApiErrors.message(res, t('bkpRunsLoadFailed')); break; }
                        const body = await res.json();
                        merged.guests = merged.guests.concat(body.guests || []);
                        merged.tasks = merged.tasks.concat(body.tasks || []);
                        const miss = new Set(body.missing || []);
                        merged.missing = merged.missing === null ? miss : new Set([...merged.missing].filter(v => miss.has(v)));
                    } catch (e) { failed = t('bkpRunsLoadFailed'); break; }
                }
                setGuests(g => ({ ...g, [run.id]: failed ? { error: failed } : { data: { ...merged, missing: [...(merged.missing || [])].sort((a, b) => a - b) } } }));
            };

            const toggleLog = async (key, upid, vmid) => {
                if (logs[key]) { setLogs(l => { const n = { ...l }; delete n[key]; return n; }); return; }
                setLogs(l => ({ ...l, [key]: { loading: true } }));
                const q = `upid=${encodeURIComponent(upid)}` + (vmid != null ? `&vmid=${vmid}` : '');
                try {
                    const res = await get(`${base}/log?${q}`);
                    if (res.ok) {
                        const body = await res.json();
                        setLogs(l => ({ ...l, [key]: { lines: body.lines || [], more: !!body.more } }));
                    } else {
                        const msg = await PegaProxApiErrors.message(res, t('bkpRunsLoadFailed'));
                        setLogs(l => ({ ...l, [key]: { error: msg } }));
                    }
                } catch (e) {
                    setLogs(l => ({ ...l, [key]: { error: t('bkpRunsLoadFailed') } }));
                }
            };

            const stateText = (s) => ({ ok: t('bkpRunsStateOk'), warning: t('bkpRunsStateWarning'), failed: t('failed'),
                running: t('bkpRunsStateRunning'), unknown: t('bkpRunsStateUnknown') })[s] || s;
            const selection = Number(job.all) === 1 ? t('all') : (job.pool ? `pool ${job.pool}` : (job.vmid || '-'));
            const meta = [job.schedule, job.storage, selection].filter(Boolean).join(' - ');
            const selectCls = isCorporate ? '' : 'px-2 py-1 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm';
            const logBox = (entry) => (
                <div className="mt-1" data-bkp-logbox>
                    {entry.loading && <div className="text-xs text-gray-400">{t('loading')}</div>}
                    {entry.error && <div className="text-xs text-red-400">{entry.error}</div>}
                    {entry.lines && (
                        <pre className="text-xs font-mono whitespace-pre-wrap break-all p-2 rounded-lg overflow-y-auto bg-proxmox-dark text-gray-300"
                            style={{ maxHeight: '260px' }}>
                            {entry.lines.join('\n')}
                        </pre>
                    )}
                </div>
            );

            const guestPanel = (run) => {
                const g = guests[run.id];
                if (!g || g.loading) return <div className="text-sm text-gray-400 p-2">{t('bkpRunsGuestsLoading')}</div>;
                if (g.error) return <div className="text-sm text-red-400 p-2">{g.error}</div>;
                const all = g.data.guests || [];
                const rank = (x) => (x.state === 'failed' ? 0 : x.state === 'unknown' ? 1 : x.state === 'running' ? 2 : 3);
                const list = all.filter(x => !onlyFailed || x.state !== 'ok').slice().sort((a, b) => rank(a) - rank(b) || a.vmid - b.vmid);
                const unread = (g.data.tasks || []).filter(x => !x.readable);
                return (
                    <div className="space-y-2 p-2" data-bkp-guests={run.id}>
                        <div className="flex flex-wrap items-center gap-3 text-xs text-gray-400">
                            <span>{bkpFill(t('bkpRunsGuestCount'), { n: all.length, failed: all.filter(x => x.state === 'failed').length })}</span>
                            <label className="flex items-center gap-1 cursor-pointer">
                                <input type="checkbox" checked={onlyFailed} onChange={e => setOnlyFailed(e.target.checked)} data-bkp-only-failed />
                                {t('bkpRunsOnlyProblems')}
                            </label>
                        </div>
                        {unread.map(x => <div key={x.upid} className="text-xs text-yellow-400">{bkpFill(t('bkpRunsTaskUnread'), { node: x.node })}</div>)}
                        {g.data.missing && g.data.missing.length > 0 && (
                            <div className="text-xs text-yellow-400" data-bkp-missing>{bkpFill(t('bkpRunsMissing'), { ids: g.data.missing.join(', ') })}</div>
                        )}
                        {!all.length && <div className="text-sm text-gray-400">{t('bkpRunsNoGuests')}</div>}
                        {list.slice(0, shown).map(x => {
                            const key = `${x.upid}#${x.vmid}`;
                            return (
                                <div key={key} className="text-sm border-t border-proxmox-border pt-1" data-bkp-guest={x.vmid} data-state={x.state}>
                                    <div className="flex items-center gap-3">
                                        <span className="font-mono text-xs text-gray-400 w-16">{x.vmid}</span>
                                        <span className="text-xs text-gray-500 w-10">{x.type === 'lxc' ? 'CT' : 'VM'}</span>
                                        <span className="text-xs text-gray-400 truncate flex-1">{x.node}</span>
                                        <span className={`text-xs ${BKP_STATE_CLS[x.state] || ''}`}>{stateText(x.state)}</span>
                                        <span className="text-xs text-gray-400 w-20 text-right">{x.took || '-'}</span>
                                        <span className="text-xs text-gray-400 w-20 text-right">{x.size || ''}</span>
                                        <button type="button" onClick={() => toggleLog(key, x.upid, x.vmid)} data-bkp-log={x.vmid}
                                            className="text-xs text-blue-400 hover:text-blue-300">
                                            {logs[key] ? t('bkpRunsHideLog') : t('bkpRunsLog')}
                                        </button>
                                    </div>
                                    {x.error && <div className="text-xs text-red-400 break-all" style={{ paddingLeft: '4rem' }}>{x.error}</div>}
                                    {logs[key] && logBox(logs[key])}
                                </div>
                            );
                        })}
                        {list.length > shown && (
                            <button type="button" onClick={() => setShown(n => n + BKP_GUEST_PAGE)} className="text-xs text-blue-400 hover:text-blue-300" data-bkp-more>
                                {bkpFill(t('bkpRunsShowMore'), { shown, total: list.length })}
                            </button>
                        )}
                        <div className="flex flex-wrap gap-3 pt-1">
                            {run.tasks.map(task => {
                                const key = `task#${task.upid}`;
                                return (
                                    <div key={key} className="w-full">
                                        <button type="button" onClick={() => toggleLog(key, task.upid, null)} data-bkp-tasklog={task.node}
                                            className="text-xs text-gray-400 hover:text-white">
                                            {bkpFill(t('bkpRunsTaskLog'), { node: task.node })}
                                        </button>
                                        {logs[key] && logBox(logs[key])}
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                );
            };

            const runsList = (data && data.runs) || [];
            const footer = (
                <button onClick={onClose} className={guestBulkButton(isCorporate, 'ghost')} data-bkp-close>{t('close')}</button>
            );
            return (
                <BackupFrame testId="bkp-runs-modal" icon={<Icons.Clock />} onClose={onClose} footer={footer}
                    title={bkpFill(t('bkpRunsTitle'), { id: job.id })} meta={meta}>
                    <div className="space-y-3" data-bkp-runs={job.id}>
                        <div className="flex flex-wrap items-center gap-3">
                            <label className="text-sm text-gray-400 flex items-center gap-2">
                                {t('bkpRunsPeriod')}
                                <select value={days} onChange={e => setDays(parseInt(e.target.value, 10))} className={selectCls} data-bkp-days>
                                    {[7, 14, 30, 60].map(d => <option key={d} value={d}>{bkpFill(t('bkpRunsDays'), { n: d })}</option>)}
                                </select>
                            </label>
                            <button type="button" onClick={load} disabled={loading} className="flex items-center gap-1 text-sm text-gray-400 hover:text-white" data-bkp-refresh>
                                <span className={`flex ${loading ? 'animate-spin' : ''}`}><Icons.RefreshCw /></span> {t('refresh')}
                            </button>
                        </div>
                        <div className="text-xs text-gray-500">{t('bkpRunsHint')}</div>
                        {error && <div className="text-sm text-red-400" data-bkp-error>{error}</div>}
                        {data && data.partial && <div className="text-xs text-yellow-400" data-bkp-partial>{t('bkpRunsPartial')}</div>}
                        {data && (data.unread_nodes || []).length > 0 && (
                            <div className="text-xs text-yellow-400" data-bkp-unread>{bkpFill(t('bkpRunsUnread'), { nodes: data.unread_nodes.join(', ') })}</div>
                        )}
                        {loading && !data && <div className="text-sm text-gray-400">{t('loading')}</div>}
                        {data && !runsList.length && <div className="text-sm text-gray-400" data-bkp-none>{t('bkpRunsNone')}</div>}
                        {runsList.length > 0 && (
                            <table className="w-full text-sm">
                                <thead>
                                    <tr className="text-left text-xs text-gray-500">
                                        <th className="p-2">{t('bkpRunsStarted')}</th>
                                        <th className="p-2">{t('duration')}</th>
                                        <th className="p-2">{t('status')}</th>
                                        <th className="p-2">{t('bkpRunsNodes')}</th>
                                        <th className="p-2">{t('bkpRunsBy')}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {runsList.map(run => (
                                        <React.Fragment key={run.id}>
                                            <tr className="border-t border-proxmox-border cursor-pointer hover:bg-proxmox-hover" data-bkp-run={run.start}
                                                data-state={run.state} onClick={() => openRun(run)}>
                                                <td className="p-2">
                                                    <span className="inline-flex items-center gap-1">
                                                        {open === run.id ? <Icons.ChevronDown /> : <Icons.ChevronRight />}
                                                        {bkpWhen(run.start)}
                                                    </span>
                                                </td>
                                                <td className="p-2 text-gray-400">{bkpTook(run.duration)}</td>
                                                <td className="p-2">
                                                    <span className={BKP_STATE_CLS[run.state] || ''}>{stateText(run.state)}</span>
                                                    {run.failed_tasks > 0 && <span className="text-xs text-gray-500"> ({bkpFill(t('bkpRunsFailedNodes'), { n: run.failed_tasks })})</span>}
                                                </td>
                                                <td className="p-2 text-gray-400">{run.tasks.length}</td>
                                                <td className="p-2 text-gray-400">{run.scheduled ? t('bkpRunsSchedule') : (run.started_by || (run.tasks[0] && run.tasks[0].user) || '-')}</td>
                                            </tr>
                                            {open === run.id && <tr><td colSpan={5}>{guestPanel(run)}</td></tr>}
                                        </React.Fragment>
                                    ))}
                                </tbody>
                            </table>
                        )}
                    </div>
                </BackupFrame>
            );
        }
        try { window.PegaProxBackupJobRunsModal = BackupJobRunsModal; } catch (_) {}

        // one backup per guest from the storage shown, restored through POST
        // /backup-restore/batch; the batch runs on the server and is followed here
        const BR_PAGE = 100;
        const BR_POLL_MS = 2500;
        const brKind = (it) => (it.subtype === 'lxc' || /\/ct\/|vzdump-lxc|vzdump-openvz/.test(it.volid || '') ? 'lxc' : 'qemu');

        function BatchRestoreModal({ clusterId, storage, items, nodes, datastores, defaultNode, startRunId, onClose }) {
            const { t } = useTranslation();
            const { getAuthHeaders, haReadOnly, haServing } = useAuth();
            const { isCorporate } = useLayout();
            const headers = useRef(getAuthHeaders);
            headers.current = getAuthHeaders;
            const call = (url, opts = {}) => fetch(url, { ...opts, credentials: 'include', headers: { ...(opts.headers || {}), ...headers.current() } });
            const [phase, setPhase] = useState(startRunId ? 'run' : (items ? 'pick' : 'runs'));
            const [filter, setFilter] = useState('');
            const [shown, setShown] = useState(BR_PAGE);
            const [picked, setPicked] = useState({});
            const [mode, setMode] = useState('new');
            const [firstVmid, setFirstVmid] = useState('');
            const [node, setNode] = useState(defaultNode || (nodes || [])[0] || '');
            const [targetStorage, setTargetStorage] = useState('');
            const [how, setHow] = useState('sequential');
            const [parallel, setParallel] = useState(2);
            const [confirmed, setConfirmed] = useState(false);
            const [busy, setBusy] = useState(false);
            const [error, setError] = useState('');
            const [refused, setRefused] = useState([]);
            const [runId, setRunId] = useState(startRunId || null);
            const [run, setRun] = useState(null);
            const [gone, setGone] = useState(false);
            const [asking, setAsking] = useState(false);
            const [recent, setRecent] = useState(null);

            const groups = useMemo(() => {
                const by = new Map();
                (items || []).forEach(it => {
                    const vmid = parseInt(it.vmid, 10);
                    if (!vmid || it.content !== 'backup' || !it.volid) return;
                    if (!by.has(vmid)) by.set(vmid, { vmid, type: brKind(it), backups: [] });
                    by.get(vmid).backups.push(it);
                });
                const out = Array.from(by.values());
                out.forEach(g => g.backups.sort((a, b) => (b.ctime || 0) - (a.ctime || 0)));
                return out.sort((a, b) => a.vmid - b.vmid);
            }, [items]);
            const q = filter.trim().toLowerCase();
            const matching = q ? groups.filter(g => String(g.vmid).includes(q)
                || g.backups.some(b => String(b.notes || '').toLowerCase().includes(q))) : groups;
            const count = Object.keys(picked).length;

            useEffect(() => {
                if (phase !== 'options' || firstVmid) return;
                call(`${API_URL}/clusters/${encodeURIComponent(clusterId)}/next-vmid`)
                    .then(r => (r.ok ? r.json() : null)).then(j => { if (j && j.vmid) setFirstVmid(String(j.vmid)); })
                    .catch(() => {});
            }, [phase]);  // eslint-disable-line react-hooks/exhaustive-deps

            // the batch as the server has it, read again while it runs
            const shownRun = useRef(runId);
            shownRun.current = runId;
            const loadRun = useCallback(async () => {
                if (!runId) return;
                try {
                    const res = await call(`${API_URL}/batch-restores/${encodeURIComponent(runId)}`);
                    if (shownRun.current !== runId) return;
                    if (res.status === 404) { setGone(true); return; }
                    if (res.ok) { const body = await res.json(); setRun(body.run); setGone(false); }
                } catch (e) { /* the next look tries again */ }
            }, [runId]);  // eslint-disable-line react-hooks/exhaustive-deps
            useEffect(() => { if (phase === 'run') loadRun(); }, [phase, loadRun]);
            const running = !!run && run.state === 'running';
            useEffect(() => {
                if (phase !== 'run' || !running) return undefined;
                const id = setInterval(loadRun, BR_POLL_MS);
                return () => clearInterval(id);
            }, [phase, running, loadRun]);

            useEffect(() => {
                if (phase !== 'runs') return;
                call(`${API_URL}/batch-restores`).then(r => (r.ok ? r.json() : { runs: [] }))
                    .then(j => setRecent((j.runs || []).filter(r => r.cluster_id === clusterId)))
                    .catch(() => setRecent([]));
            }, [phase]);  // eslint-disable-line react-hooks/exhaustive-deps

            const toggle = (g) => setPicked(p => {
                const n = { ...p };
                if (n[g.vmid]) delete n[g.vmid]; else n[g.vmid] = g.backups[0].volid;
                return n;
            });
            const choose = (g, volid) => setPicked(p => ({ ...p, [g.vmid]: volid }));
            const pickShown = () => setPicked(p => {
                const n = { ...p };
                matching.slice(0, shown).forEach(g => { if (!n[g.vmid]) n[g.vmid] = g.backups[0].volid; });
                return n;
            });

            const targetStorages = useMemo(() => {
                const ds = datastores || {};
                const list = [].concat(ds.shared || [], (ds.local || {})[node] || []);
                const seen = new Set();
                return list.filter(s => s && s.storage && /images|rootdir/.test(s.content || '') && !seen.has(s.storage) && seen.add(s.storage))
                    .map(s => s.storage);
            }, [datastores, node]);

            const firstOk = mode !== 'new' || (/^\d+$/.test(firstVmid) && parseInt(firstVmid, 10) >= 100);
            const canStart = count > 0 && !!node && firstOk && (mode !== 'overwrite' || confirmed) && !busy && !haReadOnly;

            const start = async () => {
                setBusy(true); setError(''); setRefused([]);
                const body = { items: Object.values(picked).map(volid => ({ volid })), mode, target_node: node, run: how };
                if (how === 'parallel') body.parallel = parallel;
                if (targetStorage) body.target_storage = targetStorage;
                if (mode === 'new') body.first_vmid = parseInt(firstVmid, 10);
                if (mode === 'overwrite') body.confirm = confirmed;
                let res = null;
                try {
                    res = await call(`${API_URL}/clusters/${encodeURIComponent(clusterId)}/backup-restore/batch`,
                        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
                } catch (e) { res = null; }
                setBusy(false);
                if (res && res.status === 202) {
                    const j = await res.json();
                    setRun(j.run); setRunId(j.run.id); setGone(false); setPhase('run');
                    return;
                }
                setError(await bkpError(res, t, haServing));
                const j = res ? await res.clone().json().catch(() => null) : null;
                if (j && Array.isArray(j.refused)) setRefused(j.refused);
            };

            const cancelRest = async () => {
                setBusy(true);
                let res = null;
                try { res = await call(`${API_URL}/batch-restores/${encodeURIComponent(runId)}/cancel`, { method: 'POST' }); } catch (e) { res = null; }
                setBusy(false); setAsking(false);
                if (res && res.ok) { const j = await res.json().catch(() => ({})); if (j.run) setRun(j.run); }
                else setError(await bkpError(res, t, haServing));
            };

            const stateText = (s) => ({ wait: t('batchRestoreStateWait'), restoring: t('batchRestoreStateRestoring'),
                done: t('batchRestoreStateDone'), failed: t('failed'), skipped: t('batchRestoreStateSkipped'),
                cancelled: t('batchRestoreStateCancelled'), unknown: t('bkpRunsStateUnknown') })[s] || s;
            const runText = (s) => ({ running: t('bkpRunsStateRunning'), done: t('batchRestoreStateDone'),
                cancelled: t('batchRestoreRunCancelled'), stopped: t('batchRestoreRunStopped') })[s] || s;
            const inputCls = isCorporate ? 'w-full' : 'w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-sm';
            const labelCls = 'block text-sm text-gray-400 mb-1';
            const optionCls = (on) => `w-full px-3 py-2 rounded-lg text-sm text-left border ${on ? 'border-blue-500 bg-blue-500/10' : 'border-proxmox-border'}`;
            const optionStyle = (on) => (isCorporate ? { borderColor: on ? 'var(--corp-accent, #49afd9)' : 'var(--corp-border-medium, #485764)',
                background: on ? 'var(--corp-selection, #324f61)' : 'transparent', color: 'var(--corp-text, #e9ecef)' } : undefined);

            let body = null;
            let footer = null;
            let title = t('batchRestoreTitle');
            let meta = storage ? bkpFill(t('batchRestoreFrom'), { storage }) : null;

            if (phase === 'pick') {
                body = (
                    <div className="space-y-3" data-br-pick>
                        <div className="text-sm text-gray-400">{t('batchRestorePickHint')}</div>
                        <div className="flex flex-wrap items-center gap-3">
                            <input type="text" value={filter} onChange={e => { setFilter(e.target.value); setShown(BR_PAGE); }}
                                placeholder={t('batchRestoreFilter')} className={inputCls} style={{ maxWidth: '280px' }} data-br-filter />
                            <button type="button" onClick={pickShown} className="text-xs text-blue-400 hover:text-blue-300" data-br-pick-shown>{t('batchRestorePickShown')}</button>
                            <button type="button" onClick={() => setPicked({})} className="text-xs text-gray-400 hover:text-white">{t('batchRestoreClear')}</button>
                            <span className="text-xs text-gray-400 ml-auto" data-br-count>{bkpFill(t('batchRestoreSelected'), { n: count })}</span>
                        </div>
                        {!groups.length && <div className="text-sm text-gray-400">{t('batchRestoreNothing')}</div>}
                        <div className="space-y-1">
                            {matching.slice(0, shown).map(g => {
                                const on = !!picked[g.vmid];
                                return (
                                    <div key={g.vmid} className="flex items-center gap-3 text-sm py-1 border-t border-proxmox-border" data-br-row={g.vmid}>
                                        <input type="checkbox" checked={on} onChange={() => toggle(g)} data-br-check={g.vmid} />
                                        <span className="font-mono text-xs text-gray-400 w-16">{g.vmid}</span>
                                        <span className="text-xs text-gray-500 w-8">{g.type === 'lxc' ? 'CT' : 'VM'}</span>
                                        <select value={picked[g.vmid] || g.backups[0].volid} disabled={!on}
                                            onChange={e => choose(g, e.target.value)} className={isCorporate ? 'flex-1 min-w-0 text-xs' : 'flex-1 min-w-0 px-2 py-1 bg-proxmox-dark border border-proxmox-border rounded-lg text-white text-xs'}
                                            data-br-backup={g.vmid}>
                                            {g.backups.map(b => (
                                                <option key={b.volid} value={b.volid}>
                                                    {bkpWhen(b.ctime)}{b.size_human ? ` - ${b.size_human}` : ''}{b.notes ? ` - ${String(b.notes).slice(0, 40)}` : ''}
                                                </option>
                                            ))}
                                        </select>
                                        <span className="text-xs text-gray-500 w-24 text-right">{bkpFill(t('batchRestoreBackups'), { n: g.backups.length })}</span>
                                    </div>
                                );
                            })}
                        </div>
                        {matching.length > shown && (
                            <button type="button" onClick={() => setShown(n => n + BR_PAGE)} className="text-xs text-blue-400 hover:text-blue-300" data-br-more>
                                {bkpFill(t('bkpRunsShowMore'), { shown, total: matching.length })}
                            </button>
                        )}
                    </div>
                );
                footer = (<>
                    <button onClick={onClose} className={guestBulkButton(isCorporate, 'ghost')}>{t('cancel')}</button>
                    <button onClick={() => setPhase('options')} disabled={!count} className={guestBulkButton(isCorporate, 'primary')} data-br-next>
                        {bkpFill(t('batchRestoreNext'), { n: count })}
                    </button>
                </>);
            } else if (phase === 'options') {
                body = (
                    <div className="space-y-4" data-br-options>
                        <div className="grid grid-cols-2 gap-2">
                            {['new', 'overwrite'].map(m => (
                                <button key={m} type="button" onClick={() => { setMode(m); setConfirmed(false); }} className={optionCls(mode === m)}
                                    style={optionStyle(mode === m)} data-br-mode={m} data-on={mode === m ? '1' : '0'}>
                                    <div className={`font-medium ${isCorporate ? '' : 'text-white'}`}>{m === 'new' ? t('batchRestoreModeNew') : t('batchRestoreModeOverwrite')}</div>
                                    <div className="text-xs text-gray-400">{m === 'new' ? t('batchRestoreModeNewDesc') : t('batchRestoreModeOverwriteDesc')}</div>
                                </button>
                            ))}
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <label className={labelCls}>{mode === 'new' ? t('batchRestoreNode') : t('batchRestoreNodeGone')}</label>
                                <select value={node} onChange={e => { setNode(e.target.value); setTargetStorage(''); }} className={inputCls} data-br-node>
                                    {(nodes || []).map(n => <option key={n} value={n}>{n}</option>)}
                                </select>
                            </div>
                            <div>
                                <label className={labelCls}>{t('batchRestoreStorage')}</label>
                                <select value={targetStorage} onChange={e => setTargetStorage(e.target.value)} className={inputCls} data-br-storage>
                                    <option value="">{t('batchRestoreStorageDefault')}</option>
                                    {targetStorages.map(s => <option key={s} value={s}>{s}</option>)}
                                </select>
                            </div>
                            {mode === 'new' && (
                                <div>
                                    <label className={labelCls}>{t('batchRestoreFirstId')}</label>
                                    <input type="number" min="100" value={firstVmid} onChange={e => setFirstVmid(e.target.value)} className={inputCls} data-br-first />
                                    <div className="text-xs text-gray-500 mt-1">{t('batchRestoreFirstIdHint')}</div>
                                </div>
                            )}
                            <div>
                                <label className={labelCls}>{t('batchRestoreHow')}</label>
                                <select value={how === 'sequential' ? '1' : String(parallel)} className={inputCls} data-br-how
                                    onChange={e => { const v = parseInt(e.target.value, 10); if (v === 1) setHow('sequential'); else { setHow('parallel'); setParallel(v); } }}>
                                    <option value="1">{t('batchRestoreOneByOne')}</option>
                                    {[2, 3, 4].map(n => <option key={n} value={String(n)}>{bkpFill(t('batchRestoreSomeAtOnce'), { n })}</option>)}
                                </select>
                            </div>
                        </div>
                        {mode === 'overwrite' && (
                            <label className="flex items-start gap-2 text-sm text-red-400" data-br-confirm-row>
                                <input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} className="mt-0.5" data-br-confirm />
                                <span>{bkpFill(t('batchRestoreConfirm'), { n: count })}</span>
                            </label>
                        )}
                        {error && <div className="text-sm text-red-400 break-all" data-br-error>{error}</div>}
                        {refused.length > 0 && (
                            <div className="text-xs text-red-400 space-y-0.5" data-br-refused>
                                {refused.slice(0, 50).map(r => <div key={r.volid}>{r.vmid}: {r.error}</div>)}
                            </div>
                        )}
                    </div>
                );
                footer = (<>
                    <button onClick={() => setPhase('pick')} disabled={busy} className={guestBulkButton(isCorporate, 'ghost')}>{t('batchRestoreBack')}</button>
                    <button onClick={start} disabled={!canStart} className={guestBulkButton(isCorporate, mode === 'overwrite' ? 'danger' : 'primary')} data-br-start>
                        {busy && <span className="flex animate-spin"><Icons.RotateCw /></span>}
                        {bkpFill(t('batchRestoreStart'), { n: count })}
                    </button>
                </>);
            } else if (phase === 'runs') {
                title = t('batchRestoreRecent');
                meta = null;
                body = (
                    <div className="space-y-2" data-br-runs>
                        {recent === null && <div className="text-sm text-gray-400">{t('loading')}</div>}
                        {recent && !recent.length && <div className="text-sm text-gray-400">{t('batchRestoreNoRecent')}</div>}
                        {(recent || []).map(r => {
                            const c = r.counts || {};
                            return (
                                <button key={r.id} type="button" onClick={() => { setRunId(r.id); setRun(null); setPhase('run'); }}
                                    className="w-full flex items-center gap-3 text-sm text-left py-2 border-t border-proxmox-border hover:bg-proxmox-hover" data-br-recent={r.id}>
                                    <span className={`text-xs ${BKP_STATE_CLS[r.state === 'running' ? 'running' : (c.failed ? 'failed' : 'done')]}`}>{runText(r.state)}</span>
                                    <span className="text-gray-300 flex-1 truncate">{bkpFill(t('batchRestoreFrom'), { storage: r.storage })} - {r.user}</span>
                                    <span className="text-xs text-gray-400">{bkpFill(t('batchRestoreSummary'), { done: c.done || 0, failed: c.failed || 0, total: r.total })}</span>
                                    <span className="text-xs text-gray-500">{bkpWhen(r.created)}</span>
                                </button>
                            );
                        })}
                    </div>
                );
                footer = <button onClick={onClose} className={guestBulkButton(isCorporate, 'ghost')}>{t('close')}</button>;
            } else {
                const c = (run && run.counts) || {};
                if (run) {
                    title = bkpFill(t('batchRestoreFrom'), { storage: run.storage });
                    meta = `${runText(run.state)} - ${bkpFill(t('batchRestoreSummary'), { done: c.done || 0, failed: c.failed || 0, total: run.total })}`;
                }
                const over = run ? run.total - (c.wait || 0) - (c.restoring || 0) : 0;
                body = (
                    <div className="space-y-3" data-br-run={runId}>
                        {gone && <div className="text-sm text-yellow-400" data-br-gone>{t('batchRestoreGone')}</div>}
                        {!run && !gone && <div className="text-sm text-gray-400">{t('loading')}</div>}
                        {run && (<>
                            {running && (
                                <div className="h-1.5 rounded-full bg-proxmox-dark overflow-hidden">
                                    <div className="h-full bg-blue-500" style={{ width: `${run.total ? Math.round(over * 100 / run.total) : 0}%` }} />
                                </div>
                            )}
                            {run.state === 'stopped' && run.reason && <div className="text-sm text-yellow-400">{run.reason}</div>}
                            {run.cancelled_by && <div className="text-sm text-gray-400">{bkpFill(t('batchRestoreCancelledBy'), { user: run.cancelled_by })}</div>}
                            {asking && <div className="text-sm text-yellow-400" data-br-cancel-ask>{t('batchRestoreCancelAsk')}</div>}
                            <div className="space-y-1">
                                {(run.rows || []).map(r => (
                                    <div key={r.vmid} className="text-sm border-t border-proxmox-border pt-1" data-br-run-row={r.vmid} data-state={r.state}>
                                        <div className="flex items-center gap-3">
                                            <span className="font-mono text-xs text-gray-400">{r.vmid} &gt; {r.target_vmid}</span>
                                            <span className="text-xs text-gray-500 truncate flex-1">{r.node}</span>
                                            <span className={`text-xs ${BKP_STATE_CLS[r.state] || ''}`}>
                                                {r.state === 'restoring' && <span className="inline-flex animate-spin mr-1"><Icons.RotateCw /></span>}
                                                {stateText(r.state)}
                                            </span>
                                        </div>
                                        {r.note && <div className={`text-xs break-all ${r.state === 'failed' || r.state === 'skipped' ? 'text-red-400' : 'text-gray-500'}`}>{r.note}</div>}
                                    </div>
                                ))}
                            </div>
                        </>)}
                        <div className="text-xs text-gray-400 flex items-start gap-2"><Icons.Info /><span>{t('batchRestoreServerNote')}</span></div>
                        {error && <div className="text-sm text-red-400 break-all" data-br-error>{error}</div>}
                    </div>
                );
                footer = (<>
                    {running && run.may_cancel && !haReadOnly && (asking ? (<>
                        <button onClick={() => setAsking(false)} disabled={busy} className={guestBulkButton(isCorporate, 'ghost')}>{t('batchRestoreKeep')}</button>
                        <button onClick={cancelRest} disabled={busy} className={guestBulkButton(isCorporate, 'danger')} data-br-cancel-yes>{t('batchRestoreCancelYes')}</button>
                    </>) : (
                        <button onClick={() => setAsking(true)} className={guestBulkButton(isCorporate, 'danger')} data-br-cancel>{t('batchRestoreCancel')}</button>
                    ))}
                    <button onClick={onClose} className={guestBulkButton(isCorporate, 'ghost')} data-br-close>{t('close')}</button>
                </>);
            }
            return (
                <BackupFrame testId="batch-restore-modal" icon={<Icons.RotateCcw />} onClose={onClose} footer={footer} title={title} meta={meta}>
                    {body}
                </BackupFrame>
            );
        }
        try { window.PegaProxBatchRestoreModal = BatchRestoreModal; } catch (_) {}

        // LW May 2026 — Encryption key generator. Generates server-side, shows
        // once, lets the user download the JSON envelope + a printable sheet.
        function EncryptionKeyModal({ authFetch, apiUrl, onClose }) {
            const { t } = useTranslation();
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
                w.document.write(`<!DOCTYPE html><html><head><title>${safe(t('pbsEncryptionRecoveryDocumentTitle') || 'PBS Encryption Key Recovery Sheet')}</title>
<style>body{font-family:ui-monospace,monospace;font-size:11pt;padding:24px;color:#000}
h1{font-size:14pt;margin-bottom:6px}.warn{color:#a00;font-weight:bold}
pre{white-space:pre-wrap;word-break:break-all;border:1px solid #ccc;padding:12px;background:#f7f7f7}
@media print{body{padding:0}}</style></head><body>
<h1>${safe(t('pbsEncryptionRecoveryHeading') || 'PBS Encryption Key — Recovery Sheet')}</h1>
<p class="warn">⚠ ${safe(t('pbsEncryptionRecoveryWarning') || 'Without this key, all backups encrypted with it are UNRECOVERABLE. Store offline.')}</p>
<pre>${safe(data?.recovery_sheet || '')}</pre>
<p>${safe(t('pbsJsonEnvelopeInstruction') || 'JSON envelope (paste into /etc/pve/priv/storage/<id>.enc):')}</p>
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
                                {t('pbsEncryptionKey') || 'PBS Encryption Key'}
                            </div>
                            <button onClick={onClose} className="opacity-60 hover:opacity-100 leading-none" style={{fontSize:'18px'}}>×</button>
                        </div>
                        <div className="p-5 space-y-3">
                            {!data && (
                                <>
                                    <div className="text-sm opacity-80">
                                        {t('pbsEncryptionKeyDesc') || 'Generates a fresh AES-256 encryption key in PBS format. Without this key, encrypted backups are unrecoverable — store offline.'}
                                    </div>
                                    <div style={{ background: 'rgba(245,79,71,0.08)', border: '1px solid rgba(245,79,71,0.4)',
                                                  borderRadius: '4px', padding: '8px 10px', fontSize: '12px', color: '#f54f47' }}>
                                        ⚠ {t('pbsEncryptionKeyShown') || 'The key is shown'} <strong>{t('pbsOnce') || 'once'}</strong>. {t('pbsEncryptionKeyNotRetained') || 'PegaProx does not retain a copy.'}
                                    </div>
                                    {err && <div style={{ color: '#f54f47', fontSize: '12px' }}>{err}</div>}
                                    <div className="flex justify-end">
                                        <button onClick={generate} disabled={busy}
                                            className="px-4 py-2 text-sm font-medium"
                                            style={{ background: 'var(--corp-accent, #0078a8)', color: '#fff', border: 'none', borderRadius: '3px',
                                                     opacity: busy ? 0.5 : 1 }}>
                                            {busy ? (t('pbsGeneratingEllipsis') || 'Generating…') : (t('pbsGenerateKey') || 'Generate key')}
                                        </button>
                                    </div>
                                </>
                            )}
                            {data && (
                                <>
                                    <div className="text-xs uppercase tracking-wide opacity-70">{t('pbsFingerprint') || 'Fingerprint'}</div>
                                    <div className="font-mono text-xs" style={{ wordBreak: 'break-all', padding: '6px 8px', background: 'var(--corp-surface-2, #29414e)', borderRadius: '3px' }}>
                                        {data.fingerprint}
                                    </div>
                                    <div className="text-xs uppercase tracking-wide opacity-70 mt-3">{t('pbsRecoverySheetPrintable') || 'Recovery sheet (printable)'}</div>
                                    <pre style={{ fontSize: '10.5px', maxHeight: '260px', overflowY: 'auto',
                                                  padding: '10px 12px', background: 'var(--corp-surface-2, #29414e)',
                                                  borderRadius: '3px', whiteSpace: 'pre-wrap' }}>{data.recovery_sheet}</pre>
                                    <div className="flex justify-end gap-2 pt-2" style={{ borderTop: '1px solid var(--corp-border, #29414e)' }}>
                                        <button onClick={() => download(`pbs-key-${data.fingerprint.slice(0,8)}.json`, JSON.stringify(data.key_json, null, 2), 'application/json')}
                                            className="px-3 py-1.5 text-sm"
                                            style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)', borderRadius: '3px' }}>
                                            {t('download') || 'Download'} JSON
                                        </button>
                                        <button onClick={() => download(`pbs-key-recovery-${data.fingerprint.slice(0,8)}.txt`, data.recovery_sheet)}
                                            className="px-3 py-1.5 text-sm"
                                            style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)', borderRadius: '3px' }}>
                                            {t('download') || 'Download'} .txt
                                        </button>
                                        <button onClick={printSheet}
                                            className="px-3 py-1.5 text-sm font-medium"
                                            style={{ background: 'var(--corp-accent, #0078a8)', color: '#fff', border: 'none', borderRadius: '3px' }}>
                                            {t('pbsPrintRecoverySheet') || 'Print recovery sheet'}
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
            const { t } = useTranslation();
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
            // portal to <body> so an ancestor stacking context (a transform/filter on the PBS
            // view) can't trap this fixed overlay under the PBS table — #701
            return ReactDOM.createPortal(
                <div className="fixed inset-0 z-[10010] flex items-center justify-center p-4" style={{ background: 'rgba(8,14,24,0.72)' }} onClick={onClose}>
                    <div
                        className="rounded-lg shadow-2xl w-full max-w-md"
                        style={{ background: 'var(--corp-surface, #1c2733)', color: 'var(--corp-text, #e9ecef)', border: '1px solid var(--corp-border, #29414e)' }}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <div className="px-5 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--corp-border, #29414e)' }}>
                            <div className="text-base font-semibold flex items-center gap-2">
                                <Icons.Clock className="w-4 h-4" />
                                {t('pbsAutoBackupVerification') || 'Auto Backup Verification'}
                            </div>
                            <button onClick={onClose} className="opacity-60 hover:opacity-100 leading-none" style={{fontSize:'18px'}}>×</button>
                        </div>
                        {!cfg ? (
                            <div className="p-6 text-center opacity-70">{err || (t('pbsLoadingEllipsis') || 'Loading…')}</div>
                        ) : (
                            <div className="p-5 space-y-3">
                                <p className="text-xs opacity-70">
                                    {t('pbsAutoBackupVerificationDesc') || 'Schedules a weekly backup-verification: a small set of recent snapshots is restored to scratch, booted, then cleaned up. Catches silent backup corruption.'}
                                </p>
                                <label className="flex items-center gap-3">
                                    <input type="checkbox" checked={!!cfg.enabled} onChange={(e) => update('enabled', e.target.checked)} />
                                    <span>{t('pbsEnableScheduledAutoVerification') || 'Enable scheduled auto-verification'}</span>
                                </label>
                                <div style={{ opacity: cfg.enabled ? 1 : 0.5 }}>
                                    <div className="grid grid-cols-2 gap-3">
                                        <label className="text-sm">
                                            <div className="opacity-70 mb-1">{t('day') || 'Day'}</div>
                                            <select value={cfg.day || 'sun'} onChange={(e) => update('day', e.target.value)}
                                                className="w-full px-2 py-1.5 text-sm" disabled={!cfg.enabled}
                                                style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }}>
                                                {['mon','tue','wed','thu','fri','sat','sun'].map(d => <option key={d} value={d}>{d.toUpperCase()}</option>)}
                                            </select>
                                        </label>
                                        <label className="text-sm">
                                            <div className="opacity-70 mb-1">{t('pbsHourRange') || 'Hour (0-23)'}</div>
                                            <input type="number" min="0" max="23" value={cfg.hour ?? 4}
                                                onChange={(e) => update('hour', Math.max(0, Math.min(23, parseInt(e.target.value) || 0)))}
                                                disabled={!cfg.enabled}
                                                className="w-full px-2 py-1.5 text-sm"
                                                style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }} />
                                        </label>
                                    </div>
                                    <label className="text-sm block mt-3">
                                        <div className="opacity-70 mb-1">{t('pbsSnapshotsPerRun') || 'Snapshots per run (1-50)'}</div>
                                        <input type="number" min="1" max="50" value={cfg.weekly_count ?? 5}
                                            onChange={(e) => update('weekly_count', Math.max(1, Math.min(50, parseInt(e.target.value) || 1)))}
                                            disabled={!cfg.enabled}
                                            className="w-full px-2 py-1.5 text-sm"
                                            style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }} />
                                    </label>
                                    <label className="text-sm block mt-3">
                                        <div className="opacity-70 mb-1">{t('scope') || 'Scope'}</div>
                                        <select value={cfg.scope || 'latest_per_vm'} onChange={(e) => update('scope', e.target.value)}
                                            disabled={!cfg.enabled}
                                            className="w-full px-2 py-1.5 text-sm"
                                            style={{ background: 'var(--corp-surface-2, #29414e)', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)' }}>
                                            <option value="latest_per_vm">{t('pbsLatestSnapshotPerVm') || 'Latest snapshot per VM'}</option>
                                            <option value="all">{t('pbsAllSnapshotsInPool') || 'All snapshots in pool'}</option>
                                        </select>
                                    </label>
                                </div>
                                {err && <div style={{ color: '#f54f47', fontSize: '12px' }}>{err}</div>}
                                <div className="flex justify-end gap-2 pt-2" style={{ borderTop: '1px solid var(--corp-border, #29414e)' }}>
                                    <button onClick={onClose}
                                        className="px-3 py-1.5 text-sm"
                                        style={{ background: 'transparent', color: 'var(--corp-text)', border: '1px solid var(--corp-border, #485764)', borderRadius: '3px' }}>
                                        {t('cancel') || 'Cancel'}
                                    </button>
                                    <button onClick={save} disabled={busy}
                                        className="px-3 py-1.5 text-sm font-medium"
                                        style={{ background: 'var(--corp-accent, #0078a8)', color: '#fff', border: 'none', borderRadius: '3px',
                                                 opacity: busy ? 0.5 : 1 }}>
                                        {busy ? (t('pbsSavingEllipsis') || 'Saving…') : (t('save') || 'Save')}
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>,
                document.body
            );
        }
        try { window.PegaProxVerifyScheduleModal = VerifyScheduleModal; } catch (_) {}
