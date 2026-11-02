        // ═══════════════════════════════════════════════════════════
        // Corporate Layout - Redesigned (Preview): the views - LW Oct 2026
        // The dashboard, the object header and tabs of cluster, node, VM and
        // container, and the performance charts. Only mounted from branches that
        // check useLayout().isCorpRedesigned. Every figure comes from what the
        // dashboard already holds or fetches; a value nothing reported is left
        // out instead of being drawn as a 0.
        // ═══════════════════════════════════════════════════════════

        // the thresholds the overview alerts use (AllClustersOverview), so a bar takes
        // the colour of the alert it would raise. CPU, RAM and swap
        const CR_WARN = 80;
        const CR_CRIT = 90;
        function crTone(pct) {
            if (pct == null || !Number.isFinite(pct)) return 'neutral';
            return pct > CR_CRIT ? 'error' : pct > CR_WARN ? 'warning' : 'success';
        }
        // LW Nov 2026 - storage, root disks and thin pools: one pair for the whole preview (the
        // overview alerts, the cluster table, the Datacenter page, the datastores, the node).
        // Below 70 % normal, 70 to 85 % warning (both ends included), above 85 % critical. Not
        // configurable: the server keeps no storage threshold
        const CR_STORE_WARN = 70;
        const CR_STORE_CRIT = 85;
        function crStoreTone(pct) {
            if (pct == null || !Number.isFinite(pct)) return 'neutral';
            return pct > CR_STORE_CRIT ? 'error' : pct >= CR_STORE_WARN ? 'warning' : 'success';
        }
        const crStoreScale = (t) => crFill(t('crStoreThresholds'), { warn: CR_STORE_WARN, crit: CR_STORE_CRIT });
        const crPct = (v, digits = 0) => (Number.isFinite(v) ? `${v.toFixed(digits)}%` : '-');
        const crBytes = (b) => (Number.isFinite(b) ? formatBytes(b) : '-');
        const crFill = (s, vars) => Object.keys(vars).reduce((out, k) => out.split(`{${k}}`).join(vars[k]), s || '');

        function crUptime(s) {
            if (!s) return '';
            const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
            return d > 0 ? `${d}d ${h}h ${m}m` : h > 0 ? `${h}h ${m}m` : `${m}m`;
        }

        // a percentage as a thin bar plus its number; nothing known shows a dash. tone: a view
        // with thresholds of its own (a report that names them) passes the colour in
        function CrMeter({ value, title, digits = 0, tone }) {
            if (value == null || !Number.isFinite(value)) return <span className="cr-muted" title={title}>-</span>;
            return (
                <span className={`cr-meter cr-tone-${tone || crTone(value)}`} title={title}>
                    <span className="cr-meter-track" aria-hidden="true">
                        <span className="cr-meter-fill" style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
                    </span>
                    <span className="cr-meter-val">{crPct(value, digits)}</span>
                </span>
            );
        }

        // one tile of a summary strip. meterTone: the bar's colour where crTone's limits are not
        // the ones (storage passes crStoreTone)
        function CrStat({ id, label, value, unit, sub, tone, meter, meterTone, onClick, title }) {
            const body = (
                <>
                    <span className="cr-stat-label">{label}</span>
                    <span className="cr-stat-value">{value}{unit && <span className="cr-stat-unit">{unit}</span>}</span>
                    {meter != null && (
                        <span className={`cr-stat-bar cr-tone-${meterTone || crTone(meter)}`} aria-hidden="true">
                            <span style={{ width: `${Math.min(100, Math.max(0, meter))}%` }} />
                        </span>
                    )}
                    {sub && <span className="cr-stat-sub">{sub}</span>}
                </>
            );
            const cls = `cr-stat${tone ? ' cr-stat-' + tone : ''}`;
            return onClick
                ? <button type="button" className={`${cls} cr-stat-click`} data-cr-stat={id} onClick={onClick} title={title}>{body}</button>
                : <div className={cls} data-cr-stat={id} title={title}>{body}</div>;
        }

        function CrPageHeader({ icon, title, sub, actions }) {
            return (
                <div className="cr-pagehead">
                    <div className="cr-pagehead-main">
                        {icon && <span className="cr-ico cr-pagehead-ico" aria-hidden="true">{icon}</span>}
                        <h1 className="cr-pagehead-title">{title}</h1>
                        {sub && <span className="cr-pagehead-sub">{sub}</span>}
                    </div>
                    {actions && <div className="cr-pagehead-actions">{actions}</div>}
                </div>
            );
        }

        // --- the inventory, summed up ---------------------------------------------
        // What the datacenter status of each cluster says. A cluster that is not
        // connected, or has not answered yet, adds nothing; a figure no cluster
        // reported stays null. An answer without any node is Proxmox VE not delivering
        // its cluster status (vms.py answers zeros then): its nodes are "not read"
        // (nodes null, noNodes true), its guests and resources still count.
        // nodesMissing: the connected clusters whose nodes are not in the node count.
        function crInventory(clusters, allMetrics) {
            const per = {};
            const sum = { clusters: clusters.length, connected: 0, reporting: 0, nodesMissing: 0,
                          nodes: null, vms: null, cts: null, cpu: null, mem: null, storage: null };
            const add = (key, part) => {
                if (!part) return;
                const cur = sum[key] || {};
                Object.keys(part).forEach(k => { cur[k] = (cur[k] || 0) + part[k]; });
                sum[key] = cur;
            };
            const guests = (g) => (g ? { running: g.running || 0, stopped: g.stopped || 0,
                                        total: g.total != null ? g.total : (g.running || 0) + (g.stopped || 0) } : null);
            const share = (r) => (r && r.total > 0 && Number.isFinite(r.used) ? { used: r.used, total: r.total } : null);
            clusters.forEach(c => {
                if (c.connected) sum.connected++;
                const entry = c.connected ? allMetrics?.[c.id] : null;
                const d = entry && entry.data;
                // an ESXi connection has no datacenter status and no nodes of this kind
                const counted = c.connected && c.cluster_type !== 'esxi';
                if (!d || !d.nodes) { per[c.id] = null; if (counted) sum.nodesMissing++; return; }
                sum.reporting++;
                const res = d.resources || {};
                const noNodes = !(d.nodes.total > 0);
                if (noNodes && counted) sum.nodesMissing++;
                const row = {
                    noNodes,
                    nodes: noNodes ? null : { online: d.nodes.online || 0, offline: d.nodes.offline || 0, total: d.nodes.total || 0 },
                    vms: guests(d.guests && d.guests.vms),
                    cts: guests(d.guests && d.guests.containers),
                    // XCP-ng reports no CPU in use, only the total
                    cpu: d.cluster && d.cluster.cluster_type === 'xcpng' ? null : share(res.cpu),
                    mem: share(res.memory),
                    storage: share(res.storage),
                    hardware: d.hardware || null,
                    quorate: d.cluster && d.cluster.standalone === false && d.cluster.quorate != null ? !!d.cluster.quorate : null,
                    lastUpdate: entry.lastUpdate || null,
                };
                ['cpu', 'mem', 'storage'].forEach(k => { if (row[k]) row[k].pct = row[k].used / row[k].total * 100; });
                per[c.id] = row;
                ['nodes', 'vms', 'cts'].forEach(k => add(k, row[k]));
                ['cpu', 'mem', 'storage'].forEach(k => add(k, row[k] && { used: row[k].used, total: row[k].total }));
            });
            ['cpu', 'mem', 'storage'].forEach(k => { if (sum[k]) sum[k].pct = sum[k].used / sum[k].total * 100; });
            return { sum, per };
        }

        // the alerts the overview can tell without asking anything new, each tied to its cluster
        function crAlerts(clusters, per, t) {
            const out = [];
            const what = { cpu: 'CPU', mem: 'RAM', storage: t('storage') };
            clusters.forEach(c => {
                const name = clusterLabel(c);
                if (!c.connected) {
                    out.push({ id: `${c.id}:offline`, sev: 'error', kind: 'offline', cluster: c, name, text: t('crAlertDisconnected') });
                    return;
                }
                const r = per[c.id];
                if (!r) return;
                if (r.quorate === false) out.push({ id: `${c.id}:quorum`, sev: 'error', kind: 'quorum', cluster: c, name, text: t('quorumLost') });
                // LW Nov 2026 - an offline node is critical, as the alert strip says it
                if (r.nodes && r.nodes.offline > 0) {
                    out.push({ id: `${c.id}:nodes`, sev: 'error', kind: 'nodes', cluster: c, name,
                               text: crFill(t('crAlertNodesOffline'), { n: r.nodes.offline }) });
                }
                // CPU and RAM by CR_WARN/CR_CRIT, storage by the storage pair
                ['cpu', 'mem', 'storage'].forEach(k => {
                    const pct = r[k] && r[k].pct;
                    const tone = k === 'storage' ? crStoreTone(pct) : crTone(pct);
                    if (tone !== 'warning' && tone !== 'error') return;
                    out.push({ id: `${c.id}:${k}`, sev: tone, kind: k, cluster: c, name,
                               text: crFill(t('crAlertUsage'), { what: what[k], pct: crPct(pct) }) });
                });
                const hw = r.hardware;
                if (hw && (hw.health === 'warning' || hw.health === 'critical')) {
                    out.push({ id: `${c.id}:hardware`, sev: hw.health === 'critical' ? 'error' : 'warning', kind: 'hardware',
                               cluster: c, name, text: crFill(t('crAlertHardware'), { n: hw.degraded || 0 }) });
                }
            });
            const rank = { error: 0, warning: 1 };
            return out.sort((a, b) => rank[a.sev] - rank[b.sev] || a.name.localeCompare(b.name));
        }

        // --- dashboard ------------------------------------------------------------

        function CrSummaryStrip({ inv, alerts, onShowAlerts }) {
            const { t } = useTranslation();
            const s = inv.sum;
            const offline = s.clusters - s.connected;
            const nodeOff = s.nodes ? s.nodes.total - s.nodes.online : 0;
            // LW Nov 2026 - the node count says which clusters it leaves out (no answer yet, or one without any node)
            const nodeSub = [nodeOff > 0 ? crFill(t('crNOffline'), { n: nodeOff }) : '',
                             s.nodesMissing > 0 ? crFill(t('crNodesUncounted'), { n: s.nodesMissing }) : ''].filter(Boolean).join(', ');
            const crit = alerts.filter(a => a.sev === 'error').length;
            const warn = alerts.length - crit;
            const used = (r) => crFill(t('crUsedOf'), { used: crBytes(r.used), total: crBytes(r.total) });
            return (
                <section className="cr-stat-row" aria-label={t('crSummary')} data-cr-summary="">
                    <CrStat id="clusters" label={t('clusters')} value={s.connected} unit={`/ ${s.clusters}`}
                        tone={offline > 0 ? 'error' : null}
                        sub={offline > 0 ? crFill(t('crNOffline'), { n: offline }) : t('crAllOnline')} />
                    {(s.nodes || (s.reporting > 0 && s.nodesMissing > 0)) && (
                        <CrStat id="nodes" label={t('nodes')} value={s.nodes ? s.nodes.online : '-'} unit={s.nodes ? `/ ${s.nodes.total}` : null}
                            tone={nodeOff > 0 ? 'error' : null} title={s.nodesMissing > 0 ? t('crNodesUncountedHint') : undefined}
                            sub={nodeSub || t('crAllOnline')} />
                    )}
                    {s.vms && (
                        <CrStat id="vms" label={t('crVmsRunning')} value={s.vms.running} unit={`/ ${s.vms.total}`}
                            sub={`${s.vms.stopped} ${t('stopped').toLowerCase()}`} />
                    )}
                    {s.cts && (
                        <CrStat id="cts" label={t('crCtsRunning')} value={s.cts.running} unit={`/ ${s.cts.total}`}
                            sub={`${s.cts.stopped} ${t('stopped').toLowerCase()}`} />
                    )}
                    {s.cpu && (
                        <CrStat id="cpu" label={t('cpu')} value={crPct(s.cpu.pct)} meter={s.cpu.pct}
                            sub={crFill(t('crCoresOf'), { used: s.cpu.used.toFixed(1), total: s.cpu.total })} />
                    )}
                    {s.mem && <CrStat id="mem" label={t('ram')} value={crPct(s.mem.pct)} meter={s.mem.pct} sub={used(s.mem)} />}
                    {s.storage && <CrStat id="storage" label={t('storage')} value={crPct(s.storage.pct)} meter={s.storage.pct}
                        meterTone={crStoreTone(s.storage.pct)} sub={used(s.storage)} title={crStoreScale(t)} />}
                    <CrStat id="alerts" label={t('crCriticalAlerts')} value={crit} tone={crit > 0 ? 'error' : warn > 0 ? 'warning' : null}
                        sub={crFill(t('crWarningsN'), { n: warn })} onClick={alerts.length ? onShowAlerts : undefined} />
                    {s.connected > 0 && s.reporting === 0 && (
                        <div className="cr-stat cr-stat-note" data-cr-stat="waiting">
                            <span className="cr-spinner" aria-hidden="true" />{t('crNoLiveData')}
                        </div>
                    )}
                </section>
            );
        }

        function CrClusterTable({ clusters, inv, stats, alerts, clusterGroups, onOpen }) {
            const { t } = useTranslation();
            const { holds } = crVmCan();
            const [show, setShow] = useState('all');
            const [menu, setMenu] = useState(null);
            const groups = useMemo(() => {
                const m = {};
                (clusterGroups || []).forEach(g => { m[g.id] = g.name; });
                return m;
            }, [clusterGroups]);
            const statsById = useMemo(() => {
                const m = {};
                (stats || []).forEach(s => { m[s.id] = s; });
                return m;
            }, [stats]);
            const alertsBy = useMemo(() => {
                const m = {};
                alerts.forEach(a => { (m[a.cluster.id] = m[a.cluster.id] || []).push(a); });
                return m;
            }, [alerts]);
            const rows = useMemo(() => clusters.map(c => ({
                c, r: inv.per[c.id], health: inv.per[c.id] ? (statsById[c.id] || {}).healthScore : null,
                alerts: alertsBy[c.id] || [], group: groups[c.group_id] || '',
            })), [clusters, inv, statsById, alertsBy, groups]);
            const hasGroups = Object.keys(groups).length > 0;

            const columns = useMemo(() => [
                // LW Nov 2026 - a status without any node is "not read" here as in the strip and on the
                // Datacenter page: no green dot, no Online, no 0/0
                { key: 'dot', label: '', menuLabel: t('status'), width: 30, resizable: false, sortValue: x => (x.c.connected ? (x.r && x.r.noNodes ? 0.5 : 1) : 0),
                  render: x => <span className={`cr-dot cr-dot-${!x.c.connected || x.alerts.some(a => a.sev === 'error') ? 'error' : x.r && x.r.noNodes ? 'neutral' : 'success'}`} aria-hidden="true" /> },
                { key: 'name', label: t('name'), flex: true, min: 160, sortValue: x => clusterLabel(x.c),
                  render: x => <span className="cr-strong" title={x.c.host || ''}>{clusterLabel(x.c)}</span> },
                { key: 'group', label: t('group'), width: 120, hidden: !hasGroups, sortValue: x => x.group || null, render: x => x.group },
                { key: 'status', label: t('status'), width: 104, sortValue: x => (x.c.connected ? (x.r && x.r.noNodes ? 0.5 : 1) : 0),
                  render: x => (x.c.connected && x.r && x.r.noNodes
                      ? <span data-cr-cl-state="unread" title={t('crNodesNotReadHint')}><CrBadge tone="neutral">{t('crNodesNotRead')}</CrBadge></span>
                      : <CrBadge tone={x.c.connected ? 'success' : 'error'}>{x.c.connected ? t('online') : t('offline')}</CrBadge>) },
                { key: 'nodes', label: t('nodes'), width: 80, align: 'right', mono: true, sortValue: x => (x.r && x.r.nodes ? x.r.nodes.total : null),
                  render: x => (x.r && x.r.nodes ? `${x.r.nodes.online}/${x.r.nodes.total}`
                      : x.r && x.r.noNodes ? <span className="cr-muted" data-cr-cl-nodes="unread" title={t('crNodesNotReadHint')}>-</span> : '-') },
                { key: 'vms', label: 'VMs', width: 84, align: 'right', mono: true, sortValue: x => (x.r && x.r.vms ? x.r.vms.total : null),
                  title: t('crVmsRunning'), render: x => (x.r && x.r.vms ? `${x.r.vms.running}/${x.r.vms.total}` : '-') },
                { key: 'cts', label: 'CTs', width: 84, align: 'right', mono: true, sortValue: x => (x.r && x.r.cts ? x.r.cts.total : null),
                  title: t('crCtsRunning'), render: x => (x.r && x.r.cts ? `${x.r.cts.running}/${x.r.cts.total}` : '-') },
                { key: 'cpu', label: t('cpu'), width: 118, sortValue: x => (x.r && x.r.cpu ? x.r.cpu.pct : null),
                  render: x => <CrMeter value={x.r && x.r.cpu ? x.r.cpu.pct : null} /> },
                { key: 'mem', label: t('ram'), width: 118, sortValue: x => (x.r && x.r.mem ? x.r.mem.pct : null),
                  render: x => <CrMeter value={x.r && x.r.mem ? x.r.mem.pct : null}
                      title={x.r && x.r.mem ? crFill(t('crUsedOf'), { used: crBytes(x.r.mem.used), total: crBytes(x.r.mem.total) }) : undefined} /> },
                { key: 'storage', label: t('storage'), width: 118, sortValue: x => (x.r && x.r.storage ? x.r.storage.pct : null),
                  render: x => <CrMeter value={x.r && x.r.storage ? x.r.storage.pct : null} tone={x.r && x.r.storage ? crStoreTone(x.r.storage.pct) : undefined}
                      title={x.r && x.r.storage ? `${crFill(t('crUsedOf'), { used: crBytes(x.r.storage.used), total: crBytes(x.r.storage.total) })}. ${crStoreScale(t)}` : undefined} /> },
                { key: 'health', label: t('health'), width: 76, align: 'right', mono: true, sortValue: x => x.health, title: t('crHealthBasis'),
                  render: x => (x.health != null ? <span className={`cr-tone-text cr-tone-${x.health >= 80 ? 'success' : x.health >= 60 ? 'warning' : 'error'}`}>{x.health}%</span> : '-') },
                { key: 'alerts', label: t('alerts'), width: 80, align: 'right', sortValue: x => x.alerts.length || null,
                  render: x => (x.alerts.length ? <CrBadge tone={x.alerts.some(a => a.sev === 'error') ? 'error' : 'warning'}>{x.alerts.length}</CrBadge> : '') },
                { key: 'host', label: t('host'), width: 150, hidden: true, mono: true, sortValue: x => x.c.host || null, render: x => x.c.host || '' },
                { key: 'updated', label: t('updated'), width: 96, hidden: true, mono: true,
                  sortValue: x => (x.r && x.r.lastUpdate ? new Date(x.r.lastUpdate).getTime() : null),
                  render: x => (x.r && x.r.lastUpdate ? crFmtTime(x.r.lastUpdate) : '') },
            ], [t, hasGroups]);

            const counts = useMemo(() => ({
                all: rows.length,
                online: rows.filter(x => x.c.connected).length,
                offline: rows.filter(x => !x.c.connected).length,
                alerts: rows.filter(x => x.alerts.length).length,
            }), [rows]);
            const filter = useMemo(() => (show === 'online' ? x => x.c.connected
                : show === 'offline' ? x => !x.c.connected
                : show === 'alerts' ? x => x.alerts.length > 0 : null), [show]);

            const openMenu = (x, e) => {
                const go = (tab, section) => () => onOpen(x.c, tab, section);
                setMenu({
                    back: document.activeElement,
                    position: { x: e.clientX, y: e.clientY },
                    items: [
                        { label: t('crOpen'), icon: <Icons.ArrowRight className="w-3.5 h-3.5" />, onClick: go('overview') },
                        { separator: true },
                        { label: t('resources'), icon: <Icons.Server className="w-3.5 h-3.5" />, onClick: go('resources') },
                        { label: t('datacenter'), icon: <Icons.HardDrive className="w-3.5 h-3.5" />, onClick: go('datacenter') },
                        { label: t('datastore'), icon: <Icons.Database className="w-3.5 h-3.5" />, onClick: go('datastore') },
                        { label: t('tlTab'), icon: <Icons.Clock className="w-3.5 h-3.5" />, onClick: go('timeline') },
                        { separator: true },
                        // LW Oct 2026 - the module pages of the cluster; compliance is navigation only, the health
                        // figure does not include it. It opens on Drift (three reads): the hardening sub tab asks
                        // every node over SSH as it opens
                        { label: t('insights'), icon: <Icons.Zap className="w-3.5 h-3.5" />, onClick: go('reports', 'insights') },
                        { label: t('whatifTitle'), icon: <Icons.Scale className="w-3.5 h-3.5" />, onClick: go('reports', 'whatif') },
                        ...((holds('admin.audit') || holds('node.maintenance') || holds('changes.view'))
                            ? [{ label: t('compliance'), icon: <Icons.Lock className="w-3.5 h-3.5" />,
                                 onClick: go('compliance', holds('admin.audit') || holds('node.maintenance') ? 'drift' : 'changes') }] : []),
                    ],
                });
            };
            const chips = [['all', t('all')], ['online', t('online')], ['offline', t('offline')], ['alerts', t('alerts')]];
            return (
                <>
                    <CrTable id="dash-clusters" columns={columns} rows={rows} rowKey={x => x.c.id} filter={filter} searchable
                        onRowClick={x => onOpen(x.c)} onRowContextMenu={openMenu} ariaLabel={t('clusters')}
                        initialSort={{ key: 'name', dir: 'asc' }} maxHeight={342}
                        emptyText={t('noClustersConfigured')}
                        toolbar={(
                            <>
                                <span className="cr-table-title">{t('clusters')}</span>
                                <div className="cr-seg" role="group" aria-label={t('filter')}>
                                    {chips.map(([id, label]) => (
                                        <button key={id} type="button" className={show === id ? 'active' : ''} aria-pressed={show === id}
                                            data-cr-show={id} onClick={() => setShow(id)}>
                                            {label}<span className="cr-seg-n">{counts[id]}</span>
                                        </button>
                                    ))}
                                </div>
                            </>
                        )} />
                    {menu && (
                        <ContextMenu items={menu.items} position={menu.position} onClose={() => {
                            // the keyboard goes back to the row the menu was opened on
                            const back = menu.back;
                            setMenu(null);
                            if (back && back.isConnected && back.focus) back.focus({ preventScroll: true });
                        }} />
                    )}
                </>
            );
        }

        const CR_TOP_N = 10;

        function CrTopResources({ clusters, allClusterGuests, onSelectVm }) {
            const { t } = useTranslation();
            const [by, setBy] = useState('cpu');
            const { rows, running } = useMemo(() => {
                const live = {};
                clusters.forEach(c => { if (c.connected) live[c.id] = c; });
                const list = [];
                Object.keys(allClusterGuests || {}).forEach(cid => {
                    const c = live[cid];
                    const res = allClusterGuests[cid];
                    if (!c || !Array.isArray(res)) return;
                    for (let i = 0; i < res.length; i++) {
                        const g = res[i];
                        if ((g.type !== 'qemu' && g.type !== 'lxc') || g.status !== 'running') continue;
                        list.push({ g, c, cpu: (g.cpu || 0) * 100, ram: g.maxmem > 0 ? (g.mem || 0) / g.maxmem * 100 : null });
                    }
                });
                const key = by === 'ram' ? 'ram' : 'cpu';
                list.sort((a, b) => (b[key] ?? -1) - (a[key] ?? -1));
                return { rows: list.slice(0, CR_TOP_N), running: list.length };
            }, [clusters, allClusterGuests, by]);

            const columns = useMemo(() => [
                { key: 'type', label: '', menuLabel: t('type'), width: 30, resizable: false, sortValue: x => x.g.type,
                  render: x => <span className={`cr-ico cr-guest-ico cr-guest-${x.g.type}`} title={x.g.type === 'lxc' ? t('container') : 'VM'}>
                      {x.g.type === 'lxc' ? <Icons.Box /> : <Icons.Monitor />}</span> },
                { key: 'name', label: t('name'), flex: true, min: 140, sortValue: x => x.g.name || '',
                  render: x => <span className="cr-strong">{x.g.name || `${x.g.type === 'lxc' ? 'CT' : 'VM'} ${x.g.vmid}`}</span> },
                { key: 'vmid', label: 'ID', width: 64, mono: true, align: 'right', sortValue: x => Number(x.g.vmid), render: x => x.g.vmid },
                { key: 'cluster', label: t('cluster'), width: 110, sortValue: x => clusterLabel(x.c), render: x => clusterLabel(x.c) },
                { key: 'node', label: t('node'), width: 90, sortValue: x => x.g.node || '', render: x => x.g.node || '' },
                { key: 'cpu', label: t('cpu'), width: 108, sortValue: x => x.cpu, render: x => <CrMeter value={x.cpu} digits={1} /> },
                { key: 'ram', label: t('ram'), width: 108, sortValue: x => x.ram,
                  render: x => <CrMeter value={x.ram} digits={1} title={x.g.maxmem ? crFill(t('crUsedOf'), { used: crBytes(x.g.mem || 0), total: crBytes(x.g.maxmem) }) : undefined} /> },
                { key: 'status', label: t('status'), width: 84, sortValue: x => x.g.status,
                  render: () => <CrBadge tone="success">{t('running')}</CrBadge> },
            ], [t]);

            return (
                <CrTable key={by} id="dash-top" columns={columns} rows={rows} rowKey={x => `${x.c.id}:${x.g.vmid}`}
                    onRowClick={x => onSelectVm && onSelectVm(x.c, x.g.vmid, x.g.node, x.g)} ariaLabel={t('topResources')}
                    initialSort={{ key: by, dir: 'desc' }} emptyText={t('crNoRunningGuests')} showCount={false}
                    toolbar={(
                        <>
                            <span className="cr-table-title">{t('topResources')}</span>
                            <div className="cr-seg" role="group" aria-label={t('sortBy')}>
                                {[['cpu', t('crByCpu')], ['ram', t('crByRam')]].map(([id, label]) => (
                                    <button key={id} type="button" className={by === id ? 'active' : ''} aria-pressed={by === id}
                                        data-cr-rank={id} onClick={() => setBy(id)}>{label}</button>
                                ))}
                            </div>
                            <span className="cr-table-count" data-cr-top-of="">{crFill(t('crTopOf'), { n: rows.length, total: running })}</span>
                        </>
                    )} />
            );
        }

        function CrAlertsPanel({ alerts, onOpen }) {
            const { t } = useTranslation();
            // a storage alert opens the datastores of its cluster, every other one the overview
            const open = (a) => onOpen(a.cluster, a.kind === 'storage' ? 'datastore' : 'overview');
            const columns = useMemo(() => [
                { key: 'sev', label: t('severity'), width: 92, sortValue: a => (a.sev === 'error' ? 0 : 1),
                  render: a => <CrBadge tone={a.sev}>{a.sev === 'error' ? t('critical') : t('warning')}</CrBadge> },
                { key: 'text', label: t('description'), flex: true, min: 160, sortValue: a => a.text, render: a => <span title={a.text}>{a.text}</span> },
                { key: 'cluster', label: t('cluster'), width: 120, sortValue: a => a.name,
                  render: a => <span className="cr-link">{a.name}</span> },
            ], [t]);
            return (
                <CrTable id="dash-alerts" columns={columns} rows={alerts} rowKey={a => a.id} onRowClick={open}
                    ariaLabel={t('alerts')} maxHeight={318} emptyText={t('crNoActiveAlerts')} columnMenu={false}
                    toolbar={<span className="cr-table-title">{t('alerts')}</span>} />
            );
        }

        // Recent operations: the audit trail where the user may read it (one read on open,
        // and the refresh button), otherwise what this session saw over the event stream
        function CrRecentOps({ canAudit, authFetch, events, clusters, onOpen }) {
            const { t } = useTranslation();
            const [audit, setAudit] = useState({ rows: null, loading: false, error: false, denied: false });
            const seq = useRef(0);
            // a new fetch helper from the dashboard must not read the trail again
            const fetchRef = useRef(authFetch);
            fetchRef.current = authFetch;
            const load = useCallback(async () => {
                if (!canAudit || !fetchRef.current) return;
                const n = ++seq.current;
                setAudit(a => ({ ...a, loading: true, error: false }));
                const r = await fetchRef.current(`${API_URL}/audit?limit=25`);
                if (n !== seq.current) return;
                if (r && r.status === 403) { setAudit({ rows: null, loading: false, error: false, denied: true }); return; }
                const data = r && r.ok ? await r.json().catch(() => null) : null;
                if (n !== seq.current) return;
                const rows = Array.isArray(data) ? data : (data && (data.entries || data.logs)) || null;
                setAudit({ rows, loading: false, error: !rows, denied: false });
            }, [canAudit]);
            useEffect(() => { load(); return () => { seq.current++; }; }, [load]);

            const byId = useMemo(() => {
                const m = {};
                (clusters || []).forEach(c => { m[c.id] = c; });
                return m;
            }, [clusters]);
            const fromAudit = canAudit && !audit.denied;
            const sevTone = (s) => (s === 'critical' || s === 'error' ? 'error' : s === 'warning' ? 'warning' : 'neutral');

            const auditCols = useMemo(() => [
                { key: 'sev', label: '', menuLabel: t('severity'), width: 30, resizable: false, sortValue: e => e.severity || 'info',
                  render: e => <span className={`cr-dot cr-dot-${sevTone(e.severity)}`} aria-hidden="true" /> },
                { key: 'time', label: t('time'), width: 164, mono: true, sortValue: e => e.timestamp || null, render: e => crFmtDate(e.timestamp) },
                { key: 'user', label: t('user'), width: 110, sortValue: e => e.user || null, render: e => e.user || '' },
                { key: 'action', label: t('action'), width: 160, sortValue: e => e.action || '', render: e => <span className="cr-strong">{e.action}</span> },
                { key: 'details', label: t('details'), flex: true, min: 160, sortValue: e => e.details || '',
                  render: e => <span title={e.details || ''}>{e.details || ''}</span> },
                { key: 'cluster', label: t('cluster'), width: 120, sortValue: e => e.cluster || null,
                  render: e => {
                      const c = e.cluster_id && byId[e.cluster_id];
                      if (!c) return e.cluster || '';
                      return <button type="button" className="cr-link" onClick={ev => { ev.stopPropagation(); onOpen(c); }}>{clusterLabel(c)}</button>;
                  } },
            ], [t, byId, onOpen]);
            const eventCols = useMemo(() => [
                { key: 'sev', label: '', menuLabel: t('type'), width: 30, resizable: false, sortValue: e => e.type,
                  render: e => <span className={`cr-dot cr-dot-${e.type === 'error' ? 'error' : e.type === 'success' ? 'success' : 'info'}`} aria-hidden="true" /> },
                { key: 'time', label: t('time'), width: 100, mono: true, sortValue: e => (e.time ? new Date(e.time).getTime() : null), render: e => crFmtTime(e.time) },
                { key: 'msg', label: t('description'), flex: true, min: 160, sortValue: e => e.msg || '', render: e => <span title={e.msg}>{e.msg}</span> },
                { key: 'user', label: t('user'), width: 110, sortValue: e => e.user || null, render: e => e.user || '' },
            ], [t]);

            const title = (
                <>
                    <span className="cr-table-title">{t('crRecentOps')}</span>
                    <span className="cr-table-sub" data-cr-ops-source={fromAudit ? 'audit' : 'session'}>
                        {fromAudit ? t('auditLog') : t('crSessionEvents')}
                    </span>
                </>
            );
            return fromAudit ? (
                <CrTable id="dash-ops" columns={auditCols} rows={audit.rows || []} rowKey={e => e.id ?? `${e.timestamp}:${e.action}`}
                    loading={audit.loading} error={audit.error} ariaLabel={t('crRecentOps')} maxHeight={318}
                    initialSort={{ key: 'time', dir: 'desc' }} emptyText={t('crNoRecentOps')} toolbar={title}
                    actions={(
                        <button type="button" className="cr-icon-btn" onClick={load} aria-label={t('refresh')} title={t('refresh')} data-cr-ops-refresh="">
                            <span className="cr-ico" aria-hidden="true"><Icons.RefreshCw /></span>
                        </button>
                    )} />
            ) : (
                <CrTable id="dash-events" columns={eventCols} rows={events || []} rowKey={e => e.id} ariaLabel={t('crRecentOps')}
                    maxHeight={318} emptyText={t('crNoRecentOps')} toolbar={title} />
            );
        }

        // The All Clusters view of the preview. AllClustersOverview hands over what it has
        // already worked out (clusterStats for the health score, openIn for the panels); the
        // rest is derived here. The panels below the tables are the classic ones, they fetch
        // for themselves as they do there
        function CrDashboard({ clusters, allMetrics, clusterStats, clusterGroups, allClusterGuests, recentEvents, canAudit,
                               authFetch, onSelectCluster, onSelectVm, onOpenClusterTab, onOpenGuests, addToast,
                               emptyText, onAutoInstall, openIn }) {
            const { t } = useTranslation();
            const inv = useMemo(() => crInventory(clusters, allMetrics || {}), [clusters, allMetrics]);
            const alerts = useMemo(() => crAlerts(clusters, inv.per, t), [clusters, inv, t]);
            const alertsRef = useRef(null);
            const showAlerts = () => {
                const el = alertsRef.current;
                if (!el) return;
                el.scrollIntoView({ block: 'nearest' });
                const row = el.querySelector('tr.cr-row');
                if (row) row.focus({ preventScroll: true });
            };
            const have = clusters.length > 0;
            // a cluster opens on its overview, not on whatever tab was open last
            const openCluster = useCallback((c, tab = 'overview', section) => (onOpenClusterTab ? onOpenClusterTab(c, tab, section) : onSelectCluster(c)),
                [onOpenClusterTab, onSelectCluster]);
            return (
                <div className="cr-dash" data-cr-dashboard="">
                    <CrPageHeader icon={<Icons.Grid />} title={t('inventoryOverview')}
                        actions={have && (
                            <>
                                {onOpenGuests && (
                                    <button type="button" data-all-guests-link onClick={onOpenGuests} className="cr-btn cr-btn-ghost">
                                        <span className="cr-ico" aria-hidden="true"><Icons.Monitor /></span>{t('allGuestsTitle')}
                                    </button>
                                )}
                                <InventoryCsvButton clusters={clusters} addToast={addToast} label={t('inventoryCsv')} className="cr-btn cr-btn-ghost" />
                            </>
                        )} />
                    {!have ? (
                        <div className="cr-panel cr-empty" data-cr-empty="">
                            <Icons.Server className="w-6 h-6" />
                            <p>{emptyText}</p>
                            {onAutoInstall && <button type="button" className="cr-btn cr-btn-primary" onClick={onAutoInstall}>{t('autoInstallFirstHost')}</button>}
                        </div>
                    ) : (
                        <>
                            <CrSummaryStrip inv={inv} alerts={alerts} onShowAlerts={showAlerts} />
                            <CrClusterTable clusters={clusters} inv={inv} stats={clusterStats} alerts={alerts}
                                clusterGroups={clusterGroups} onOpen={openCluster} />
                            <div className="cr-dash-grid">
                                <CrTopResources clusters={clusters} allClusterGuests={allClusterGuests} onSelectVm={onSelectVm} />
                                <div ref={alertsRef} className="cr-dash-cell">
                                    <CrAlertsPanel alerts={alerts} onOpen={openCluster} />
                                </div>
                            </div>
                            <CrRecentOps canAudit={canAudit} authFetch={authFetch} events={recentEvents} clusters={clusters}
                                onOpen={openCluster} />
                            <GuestsWithoutBackup clusters={clusters} onSelectVm={onSelectVm} />
                            <StorageOverview clusters={clusters} />
                            <CephOverview clusters={clusters} onOpen={openIn && openIn('datacenter', 'ceph')} />
                            <PendingUpdatesOverview clusters={clusters} onOpen={openIn && openIn('settings', 'updates')} />
                        </>
                    )}
                </div>
            );
        }

        // --- object views ---------------------------------------------------------

        // The head of every object view: what it is, its state, where it sits, and the actions
        // the classic view offers here (passed in as they are, with their own confirmations)
        function CrObjectHeader({ kind, icon, name, id, status, badges, meta, actions, onBack }) {
            const { t } = useTranslation();
            const facts = (meta || []).filter(m => m && m.value != null && m.value !== '' && m.value !== false);
            return (
                <div className="cr-objhead" data-cr-objhead={kind}>
                    <div className="cr-objhead-main">
                        {onBack && (
                            <button type="button" className="cr-icon-btn" onClick={onBack} title={t('backToList')} aria-label={t('backToList')}>
                                <Icons.ChevronLeft />
                            </button>
                        )}
                        <span className={`cr-objhead-icon cr-objhead-icon-${kind}`} aria-hidden="true">{icon}</span>
                        <div className="cr-objhead-text">
                            <div className="cr-objhead-title">
                                <h2 className="cr-objhead-name" title={typeof name === 'string' ? name : undefined}>{name}</h2>
                                {id != null && id !== '' && <span className="cr-objhead-id" data-cr-objid="">{id}</span>}
                                {status}
                                {badges}
                            </div>
                            {facts.length > 0 && (
                                <dl className="cr-objhead-meta">
                                    {facts.map(m => (
                                        <div key={m.key} className="cr-meta" data-cr-meta={m.key}>
                                            <dt>{m.label}</dt>
                                            <dd className={m.mono ? 'cr-mono' : undefined} title={typeof m.value === 'string' ? m.value : undefined}>{m.value}</dd>
                                        </div>
                                    ))}
                                </dl>
                            )}
                        </div>
                    </div>
                    {actions && <div className="cr-objhead-actions corp-toolbar" role="toolbar" aria-label={t('actions')}>{actions}</div>}
                </div>
            );
        }

        // Tabs with the arrow keys, Home and End; a tab that is picked by key is opened too
        function CrTabs({ id, tabs, active, onChange, label }) {
            const refs = useRef({});
            const list = (tabs || []).filter(Boolean);
            const current = list.some(x => x.id === active) ? active : (list[0] && list[0].id);
            const onKey = (e, i) => {
                let j = null;
                if (e.key === 'ArrowRight') j = (i + 1) % list.length;
                else if (e.key === 'ArrowLeft') j = (i - 1 + list.length) % list.length;
                else if (e.key === 'Home') j = 0;
                else if (e.key === 'End') j = list.length - 1;
                if (j == null) return;
                e.preventDefault();
                onChange(list[j].id);
                const el = refs.current[list[j].id];
                if (el) el.focus();
            };
            return (
                <div className="corp-tab-strip cr-tabs" role="tablist" aria-label={label} data-cr-tabs={id}>
                    {list.map((tab, i) => {
                        const on = tab.id === active;
                        return (
                            <button key={tab.id} type="button" role="tab" aria-selected={on} tabIndex={tab.id === current ? 0 : -1}
                                ref={el => { refs.current[tab.id] = el; }} className={on ? 'active' : ''}
                                onClick={() => onChange(tab.id)} onKeyDown={e => onKey(e, i)} data-cr-tab={tab.id} {...(tab.hook || {})}>
                                {tab.icon && <span className="cr-ico" aria-hidden="true">{tab.icon}</span>}
                                <span>{tab.label}</span>
                            </button>
                        );
                    })}
                </div>
            );
        }

        // the status of a node or guest as a badge
        function CrStateBadge({ state }) {
            const { t } = useTranslation();
            const map = {
                running: ['success', t('running')], online: ['success', t('online')],
                stopped: ['neutral', t('stopped')], paused: ['warning', t('paused')],
                maintenance: ['warning', t('maintenance')], offline: ['error', t('offline')],
            };
            const [tone, label] = map[state] || ['neutral', state || '-'];
            return <span data-cr-state={state}><CrBadge tone={tone}>{label}</CrBadge></span>;
        }

        // The head of a cluster's overview. The buttons are the classic header's, behind the
        // same checks: a handler the dashboard does not pass is a button that is not there
        function CrClusterHeader({ cluster, status, healthBadge, onRefresh, onRename, onReconfigure, onDelete }) {
            const { t } = useTranslation();
            const dc = status && status.nodes ? status : null;
            const g = dc && dc.guests;
            const guests = g && (g.vms || g.containers)
                ? { running: ((g.vms && g.vms.running) || 0) + ((g.containers && g.containers.running) || 0),
                    total: ((g.vms && g.vms.total) || 0) + ((g.containers && g.containers.total) || 0) } : null;
            // nodes and quorum stay on the services bar under the head, which reads them live
            const info = dc && dc.cluster;
            const icon = (Icon, label, fn, extra = '') => fn && (
                <button type="button" className={`cr-icon-btn${extra}`} onClick={fn} title={label} aria-label={label}>
                    <span className="cr-ico" aria-hidden="true"><Icon /></span>
                </button>
            );
            return (
                <CrObjectHeader kind="cluster" icon={<Icons.Database />} name={clusterLabel(cluster)} id={cluster.host}
                    status={<CrStateBadge state={cluster.connected ? 'online' : 'offline'} />}
                    badges={healthBadge}
                    meta={[
                        info && info.standalone && { key: 'mode', label: t('type'), value: t('crStandalone') },
                        guests && { key: 'guests', label: t('guests'), value: `${guests.running}/${guests.total} ${t('running').toLowerCase()}` },
                        info && info.name && info.name !== clusterLabel(cluster) && { key: 'pve', label: t('crPveCluster'), value: info.name },
                    ]}
                    actions={(
                        <>
                            <button type="button" className="cr-btn" onClick={onRefresh} data-cr-refresh="">
                                <span className="cr-ico" aria-hidden="true"><Icons.RotateCw /></span>{t('refreshData')}
                            </button>
                            {icon(Icons.Edit, t('renameCluster'), onRename)}
                            {icon(Icons.Settings, t('reconfigureCluster'), onReconfigure)}
                            {icon(Icons.Trash, t('deleteCluster'), onDelete, ' cr-icon-danger')}
                        </>
                    )} />
            );
        }

        // the summary of a cluster's own overview, from the values the overview worked out
        function CrClusterSummary({ cpu, cpuSub, mem, storage, guests, children }) {
            const { t } = useTranslation();
            const used = (r) => crFill(t('crUsedOf'), { used: crBytes(r.used), total: crBytes(r.total) });
            return (
                <section className="cr-stat-row" aria-label={t('crSummary')} data-cr-cluster-summary="">
                    {cpu != null && <CrStat id="cpu" label={t('clusterCpu')} value={crPct(cpu, 1)} meter={cpu} sub={cpuSub} />}
                    {mem && <CrStat id="mem" label={t('clusterMemory')} value={crPct(mem.pct, 1)} meter={mem.pct} sub={used(mem)} />}
                    {storage && <CrStat id="storage" label={t('clusterStorage')} value={crPct(storage.pct, 1)} meter={storage.pct} sub={used(storage)} />}
                    {guests && <CrStat id="guests" label={t('guests')} value={guests.running} unit={`/ ${guests.total}`}
                        sub={`${guests.running} ${t('runningOf')} ${guests.total}`} />}
                    {children}
                </section>
            );
        }

        // --- performance charts ---------------------------------------------------

        // the presets the metrics endpoints take (there is no 6 hour one). A view with presets of
        // its own (the report maps some to from/to) passes them as [[id, label], ...]
        function CrTimeRange({ value, onChange, ranges: own }) {
            const { t } = useTranslation();
            const ranges = own || [['hour', t('crRange1h')], ['day', t('crRange24h')], ['week', t('crRange7d')],
                                   ['month', t('crRange30d')], ['year', t('crRange1y')]];
            return (
                <div className="cr-seg cr-range" role="group" aria-label={t('crTimeRange')}>
                    {ranges.map(([id, label]) => (
                        <button key={id} type="button" className={value === id ? 'active' : ''} aria-pressed={value === id}
                            data-cr-range={id} onClick={() => { if (value !== id) onChange(id); }}>{label}</button>
                    ))}
                </div>
            );
        }

        // the series colours, read from the tokens of the theme on screen (LineChart wants hex)
        function crSeriesColors() {
            let css = null;
            try { css = getComputedStyle(document.body); } catch (_) {}
            const v = (name, fallback) => {
                const s = css ? css.getPropertyValue(name).trim() : '';
                return /^#[0-9a-f]{6}$/i.test(s) ? s : fallback;
            };
            return { cpu: v('--corp-metric-cpu', '#55b6d0'), ram: v('--corp-metric-ram', '#a383c9'),
                     disk: v('--corp-metric-disk', '#64b94a'), net: v('--corp-metric-net', '#e5b83d') };
        }

        const crHasSamples = (a) => Array.isArray(a) && a.some(v => typeof v === 'number' && Number.isFinite(v));
        // true when any series of a metrics answer holds a sample
        function crAnySamples(answer) {
            const m = answer && answer.metrics;
            return !!m && Object.keys(m).some(k => crHasSamples(m[k]));
        }

        // none: what an empty chart says instead of "No data" when the view knows why. LW Nov 2026 -
        // toggles: a chart of several series gets a button per series (instead of the canvas legend),
        // what is switched off stays off when the chart draws again; caption: a line under the chart
        function CrChart({ id, label, series, datasets, timestamps, wide, none, toggles, caption, ...rest }) {
            const { t } = useTranslation();
            const [off, setOff] = useState(() => new Set());
            const has = datasets ? datasets.some(d => crHasSamples(d.data)) : crHasSamples(series && series.data);
            const cls = `cr-chart-cell${wide ? ' cr-chart-wide' : ''}`;
            if (!has) {
                return (
                    <div className={`${cls} cr-chart-none`} data-cr-chart={id}>
                        <span className="cr-chart-title">{label}</span>
                        <span className="cr-muted">{none || t('noData')}</span>
                    </div>
                );
            }
            const own = !!(toggles && datasets && datasets.length > 1);
            const shown = own ? datasets.map(d => (off.has(d.label) ? { ...d, hidden: true } : d)) : datasets;
            const flip = (name) => setOff(prev => { const n = new Set(prev); if (n.has(name)) n.delete(name); else n.add(name); return n; });
            return (
                <div className={`${cls}${own || caption ? ' cr-chart-more' : ''}`} data-cr-chart={id}>
                    {datasets
                        ? <LineChart label={label} datasets={shown} timestamps={timestamps} {...(own ? { legend: false } : {})} {...rest} />
                        : <LineChart label={label} {...series} {...rest} />}
                    {own && (
                        <span className="cr-chart-series" role="group" aria-label={crFill(t('crPfSeriesOf'), { what: label })}>
                            {datasets.map(d => (
                                <button key={d.label} type="button" className="cr-chart-toggle" aria-pressed={!off.has(d.label)}
                                    data-cr-series={d.label} onClick={() => flip(d.label)}
                                    title={off.has(d.label) ? t('crPfSeriesShow') : t('crPfSeriesHide')}>
                                    <span className="cr-chart-swatch" aria-hidden="true"
                                        style={{ borderTopColor: d.color, borderTopStyle: d.dash ? 'dashed' : 'solid' }} />
                                    {d.label}
                                </button>
                            ))}
                        </span>
                    )}
                    {caption && <span className="cr-chart-caption" data-cr-chart-caption="">{caption}</span>}
                </div>
            );
        }

        // state: loading, error, empty or ready. busy: a newer range is on its way while the
        // charts still show the last one. ranges, errorText and footer (notes under the charts)
        // are for a view that has its own presets and knows what went wrong. LW Nov 2026 - tools:
        // buttons beside the presets; quality: what the charts are made of, right under them;
        // more: the groups a user opens below, inside the zoom of the charts while they are drawn
        function CrPerfPanel({ title, range, onRange, zoom, state, emptyText, onRetry, busy, charts, ranges, errorText, footer,
                               tools, quality, more }) {
            const { t } = useTranslation();
            let body;
            if (state === 'loading') {
                body = <div className="cr-perf-state" role="status"><span className="cr-spinner" aria-hidden="true" />{t('loading')}</div>;
            } else if (state === 'error') {
                body = (
                    <div className="cr-perf-state cr-perf-error" role="alert">
                        <span>{errorText || t('crPerfFailed')}</span>
                        {onRetry && <button type="button" className="cr-btn" onClick={onRetry} data-cr-perf-retry="">{t('retry')}</button>}
                    </div>
                );
            } else if (state === 'empty') {
                body = <div className="cr-perf-state" role="status">{emptyText || t('crPerfEmpty')}</div>;
            } else {
                body = (
                    <ChartZoomContext.Provider value={zoom || null}>
                        <div className="cr-chart-grid">
                            {charts.map(c => <CrChart key={c.id} {...c} />)}
                        </div>
                    </ChartZoomContext.Provider>
                );
            }
            return (
                <CrPanel title={title} className="cr-perf" data-cr-perf={state}
                    actions={(
                        <>
                            {zoom && state === 'ready' && <ChartZoomBar zoom={zoom} />}
                            {busy && state === 'ready' && <span className="cr-spinner" role="status" aria-label={t('loading')} />}
                            {tools}
                            <CrTimeRange value={range} onChange={onRange} ranges={ranges} />
                        </>
                    )}>
                    {body}
                    {quality}
                    {more && <ChartZoomContext.Provider value={state === 'ready' ? (zoom || null) : null}>{more}</ChartZoomContext.Provider>}
                    {footer}
                </CrPanel>
            );
        }
