        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned (Preview): the network of a node - LW Nov 2026
        // CorporateNodeDetailView (node_modals.js) keeps its reads, the create and edit dialogs and
        // their saves. For a Proxmox VE node in the preview the Configure > Network sub tab is drawn
        // here: the interfaces by kind with what each is built from, what waits for Apply (the diff
        // Proxmox VE keeps for interfaces.new, read from GET .../network/changes) and Apply and
        // Revert behind a summary and a confirmation. Apply has no automatic rollback, and the
        // dialog says so. The requests are the classic ones: PUT and DELETE .../network.
        // ═══════════════════════════════════════════════════════════

        const CR_NN_GROUPS = ['physical', 'bond', 'bridge', 'vlan', 'other'];
        const CR_NN_CREATE = [['bridge', 'Linux Bridge'], ['bond', 'Linux Bond'], ['vlan', 'Linux VLAN'],
                              ['OVSBridge', 'OVS Bridge'], ['OVSBond', 'OVS Bond'], ['OVSIntPort', 'OVS IntPort']];

        function crNnT(t, key, vars) {
            let s = t(key);
            for (const k of Object.keys(vars || {})) s = s.split(`{${k}}`).join(String(vars[k]));
            return s;
        }

        const crNnWords = (v) => String(v == null ? '' : v).split(/[\s,]+/).filter(Boolean);

        function crNnGroup(row) {
            const ty = String((row && row.type) || '');
            if (ty === 'eth') return 'physical';
            if (ty === 'bond' || ty === 'OVSBond') return 'bond';
            if (ty === 'bridge' || ty === 'OVSBridge') return 'bridge';
            if (ty === 'vlan') return 'vlan';
            return 'other';
        }

        // the device under a VLAN: vlan-raw-device, else the part in front of the dot (eno1.20, vmbr0.20)
        function crNnVlanParent(row) {
            if (row['vlan-raw-device']) return String(row['vlan-raw-device']);
            const m = /^(.+)\.(\d+)$/.exec(String(row.iface || ''));
            return m ? m[1] : '';
        }
        function crNnVlanTag(row) {
            if (row['vlan-id'] != null && row['vlan-id'] !== '') return String(row['vlan-id']);
            const m = /\.(\d+)$/.exec(String(row.iface || ''));
            return m ? m[1] : '';
        }

        // what an interface is built from, as the list says it: bond members, bridge ports, the
        // device under a VLAN, the bridge an OVS internal port sits on
        function crNnLower(row) {
            const g = crNnGroup(row);
            if (g === 'bond') return [...new Set([...crNnWords(row.slaves), ...crNnWords(row.ovs_bonds)])];
            if (g === 'bridge') return [...new Set([...crNnWords(row.bridge_ports), ...crNnWords(row.ovs_ports)])];
            if (g === 'vlan') { const p = crNnVlanParent(row); return p ? [p] : []; }
            if (row.type === 'OVSIntPort' && row.ovs_bridge) return [String(row.ovs_bridge)];
            return [];
        }

        function crNnModel(rows) {
            const list = (Array.isArray(rows) ? rows : []).filter(r => r && typeof r === 'object' && r.iface != null && r.iface !== '');
            const byName = new Map(list.map(r => [String(r.iface), r]));
            const lower = new Map();
            const upper = new Map();
            for (const r of list) {
                const name = String(r.iface);
                const l = crNnLower(r).filter(d => d !== name);
                lower.set(name, l);
                for (const d of l) {
                    if (!upper.has(d)) upper.set(d, []);
                    upper.get(d).push(name);
                }
            }
            const groups = {};
            for (const g of CR_NN_GROUPS) groups[g] = [];
            const byNameSort = (a, b) => String(a.iface).localeCompare(String(b.iface), undefined, { numeric: true });
            for (const r of [...list].sort(byNameSort)) groups[crNnGroup(r)].push(r);
            // a chain is drawn for each interface that is built from something and that nothing is built on
            const tops = list.filter(r => (lower.get(String(r.iface)) || []).length > 0 && !(upper.get(String(r.iface)) || []).length)
                .map(r => String(r.iface)).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
            return { list, byName, lower, upper, groups, tops };
        }

        // the chain under an interface as tokens: eno1 + eno2 -> bond0 -> vmbr0. A device with a chain
        // of its own next to another one is put in brackets, a loop in the config stops the walk
        function crNnChain(model, name, seen) {
            const path = new Set(seen || []);
            if (path.has(name)) return [{ k: 'if', name, loop: true }];
            path.add(name);
            const l = model.lower.get(name) || [];
            if (!l.length) return [{ k: 'if', name }];
            const parts = l.map(d => crNnChain(model, d, path));
            const out = [];
            parts.forEach((p, i) => {
                if (i > 0) out.push({ k: 'plus' });
                const wrap = parts.length > 1 && p.some(x => x.k === 'arrow');
                if (wrap) out.push({ k: 'open' });
                out.push(...p);
                if (wrap) out.push({ k: 'close' });
            });
            out.push({ k: 'arrow' }, { k: 'if', name });
            return out;
        }

        // every device under an interface, recursively
        function crNnBelow(model, name, acc) {
            const out = acc || new Set();
            for (const d of model.lower.get(name) || []) {
                if (out.has(d)) continue;
                out.add(d);
                crNnBelow(model, d, out);
            }
            return out;
        }

        // --- what waits for Apply -----------------------------------------------------------------
        // The text is diff -u of the running interfaces file against interfaces.new. A changed line
        // belongs to the block of the last "auto", "allow-..." or "iface" line before it in its hunk;
        // a line in front of the first of those in a hunk belongs to a block the hunk does not show
        // and stays untied. Blank lines are not counted as a change of an interface.
        const CR_NN_STANZA = /^(auto|allow(?:-[\w-]+)|iface)\s+(.+)$/;

        function crNnParseDiff(text) {
            const out = { known: typeof text === 'string', empty: true, lines: [], ifaces: {}, untied: 0, added: 0, removed: 0, changed: [] };
            if (typeof text !== 'string' || !text.trim()) return out;
            out.empty = false;
            let cur = [];
            let inHunk = false;
            const touch = (names, sign, body) => {
                for (const n of names) {
                    const e = out.ifaces[n] || (out.ifaces[n] = { add: 0, del: 0, ifaceAdd: false, ifaceDel: false });
                    if (sign === '+') e.add += 1; else e.del += 1;
                    if (/^iface\s/.test(body)) { if (sign === '+') e.ifaceAdd = true; else e.ifaceDel = true; }
                }
            };
            for (const raw of text.replace(/\r/g, '').split('\n')) {
                if (/^(---|\+\+\+) /.test(raw) && !inHunk) { out.lines.push({ kind: 'file', text: raw }); continue; }
                if (raw.startsWith('@@')) { inHunk = true; cur = []; out.lines.push({ kind: 'hunk', text: raw }); continue; }
                if (!inHunk) { if (raw) out.lines.push({ kind: 'meta', text: raw }); continue; }
                const sign = raw.charAt(0);
                if (sign !== '+' && sign !== '-' && sign !== ' ') {
                    if (raw) out.lines.push({ kind: 'meta', text: raw });
                    continue;
                }
                const body = raw.slice(1);
                const st = CR_NN_STANZA.exec(body);
                if (st) {
                    const names = st[1] === 'iface' ? [st[2].split(/\s+/)[0]] : st[2].split(/\s+/).filter(Boolean);
                    cur = names.filter(n => n !== 'lo');
                } else if (body && !/^\s/.test(body) && !body.startsWith('#')) {
                    // source, mapping or another top level line: no interface block
                    cur = [];
                }
                const kind = sign === '+' ? 'add' : sign === '-' ? 'del' : 'ctx';
                out.lines.push({ kind, text: raw, ifaces: cur.slice() });
                if (kind === 'ctx' || !body.trim()) continue;
                if (kind === 'add') out.added += 1; else out.removed += 1;
                out.changed.push({ sign, body });
                if (cur.length) touch(cur, sign, body);
                else out.untied += 1;
            }
            for (const n of Object.keys(out.ifaces)) {
                const e = out.ifaces[n];
                e.state = e.ifaceAdd && !e.ifaceDel ? 'new' : e.ifaceDel && !e.ifaceAdd ? 'removed' : 'changed';
            }
            return out;
        }

        // --- the address PegaProx uses ----------------------------------------------------------------
        const crNnIsIp = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || (/^[0-9a-f:.]+$/i.test(s) && s.includes(':'));
        const crNnBare = (s) => String(s || '').trim().replace(/\/\d+$/, '').toLowerCase();

        function crNnAddrs(row) {
            const out = [];
            for (const k of ['cidr', 'address', 'cidr6', 'address6']) {
                const v = crNnBare(row[k]);
                if (v && !out.includes(v)) out.push(v);
            }
            return out;
        }

        // the cluster host as configured: an address (also [v6]:port or v4:port) or a name
        function crNnHost(host) {
            let h = String(host || '').trim();
            const v6 = /^\[([^\]]+)\](?::\d+)?$/.exec(h);
            if (v6) h = v6[1];
            else if (/^[^:]+:\d+$/.test(h)) h = h.replace(/:\d+$/, '');
            return h.toLowerCase();
        }

        // where the addresses PegaProx uses sit: the node's own address (GET .../ip, not a stand-in)
        // and the API host of the cluster when it is an address. A name cannot be matched here.
        function crNnManagement(model, { nodeIp, nodeIpStandIn, clusterHost }) {
            const targets = [];
            const ip = crNnBare(nodeIp);
            if (ip && !nodeIpStandIn) targets.push({ addr: ip, role: 'node' });
            const host = crNnHost(clusterHost);
            let hostName = '';
            if (host && crNnIsIp(host)) {
                const same = targets.find(x => x.addr === host);
                if (same) same.role = 'both'; else targets.push({ addr: host, role: 'api' });
            } else if (host) hostName = host;
            const carriers = [];
            for (const r of model.list) {
                const addrs = crNnAddrs(r);
                for (const x of targets) if (addrs.includes(x.addr)) carriers.push({ iface: String(r.iface), addr: x.addr, role: x.role });
            }
            const chain = new Set();
            for (const c of carriers) {
                chain.add(c.iface);
                crNnBelow(model, c.iface, chain);
            }
            // what is built from a part of the chain without being in it: a bond or a bridge takes
            // its ports for itself, so one that waits on a port of the carrier pulls that port away.
            // A VLAN or an OVS internal port sits on top of a device and takes nothing
            const takes = new Map();
            for (const r of model.list) {
                const name = String(r.iface);
                const g = crNnGroup(r);
                if (chain.has(name) || g === 'physical' || g === 'vlan' || r.type === 'OVSIntPort') continue;
                const got = (model.lower.get(name) || []).filter(d => chain.has(d));
                if (got.length) takes.set(name, got);
            }
            const unmatched = targets.filter(x => !carriers.some(c => c.addr === x.addr));
            // the API host on no interface here is another node's address: this node's change does not
            // reach it (a pending line that names it still counts, see crNnRisk). The node's own
            // address on no interface means the page does not know where it is
            const lost = unmatched.filter(x => x.role !== 'api');
            return { targets, carriers, chain, takes, unmatched, lost, hostName, nodeUnknown: !ip || !!nodeIpStandIn };
        }

        // what Apply means for that address: 'touch' (a waiting change is on the carrier, under it,
        // takes a port of it, or names the address), 'unsure' (the page cannot rule it out) or 'clear'
        function crNnRisk(mgmt, diff) {
            const hits = [];
            const takers = [];
            if (diff.known && !diff.empty) {
                for (const n of Object.keys(diff.ifaces)) {
                    if (mgmt.chain.has(n)) hits.push(n);
                    else if (mgmt.takes && mgmt.takes.has(n)) takers.push({ iface: n, takes: mgmt.takes.get(n) });
                }
            }
            const named = [];
            if (diff.known && !diff.empty) {
                for (const x of mgmt.targets) {
                    const re = new RegExp(`(^|[^0-9a-f:.])${x.addr.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![0-9a-f:.])`, 'i');
                    if (diff.changed.some(l => re.test(l.body))) named.push(x.addr);
                }
            }
            const reasons = [];
            if (!diff.known) reasons.push('diff');
            if (diff.untied > 0) reasons.push('untied');
            if (mgmt.nodeUnknown) reasons.push('nodeip');
            if (mgmt.lost.length) reasons.push('unmatched');
            if (mgmt.hostName) reasons.push('hostname');
            let level = 'clear';
            if (hits.length || named.length || takers.length) level = 'touch';
            else if (reasons.length && !(diff.known && diff.empty)) level = 'unsure';
            return { level, hits, named, takers, reasons };
        }

        window.PegaProxNodeNet = Object.freeze({ model: crNnModel, chain: crNnChain, parseDiff: crNnParseDiff,
                                                 management: crNnManagement, risk: crNnRisk, group: crNnGroup });

        // --- the view ---------------------------------------------------------------------------------

        function CrNnChainView({ model, name, marks }) {
            const tokens = crNnChain(model, name);
            return (
                <div className="cr-nn-chain" data-cr-nn-chain={name}>
                    {tokens.map((x, i) => {
                        if (x.k === 'plus') return <span key={i} className="cr-nn-op" aria-hidden="true">+</span>;
                        if (x.k === 'arrow') return <span key={i} className="cr-nn-op cr-nn-arrow" aria-label="->"><Icons.ArrowRight /></span>;
                        if (x.k === 'open') return <span key={i} className="cr-nn-op" aria-hidden="true">(</span>;
                        if (x.k === 'close') return <span key={i} className="cr-nn-op" aria-hidden="true">)</span>;
                        const m = marks(x.name);
                        return (
                            <span key={i} className={`cr-nn-chip cr-nn-chip-${m.group}${m.pending ? ' cr-nn-chip-pending' : ''}${m.mgmt ? ' cr-nn-chip-mgmt' : ''}${m.missing ? ' cr-nn-chip-missing' : ''}`}
                                data-cr-nn-chip={x.name} title={m.title}>{x.name}{x.loop ? ' ...' : ''}</span>
                        );
                    })}
                </div>
            );
        }

        function crNnRole(t, model, row) {
            const name = String(row.iface);
            const g = crNnGroup(row);
            const up = (model.upper.get(name) || []).slice().sort();
            if (g === 'physical' || g === 'other') {
                const bonds = up.filter(u => crNnGroup(model.byName.get(u) || {}) === 'bond');
                const bridges = up.filter(u => crNnGroup(model.byName.get(u) || {}) === 'bridge');
                const vlans = up.filter(u => crNnGroup(model.byName.get(u) || {}) === 'vlan');
                if (bonds.length) return crNnT(t, 'crNnRoleBondMember', { name: bonds.join(', ') });
                if (bridges.length) return crNnT(t, 'crNnRoleBridgePort', { name: bridges.join(', ') });
                if (vlans.length) return crNnT(t, 'crNnRoleVlanBase', { name: vlans.join(', ') });
                return row.type === 'OVSIntPort' && row.ovs_bridge ? crNnT(t, 'crNnRoleOnBridge', { name: row.ovs_bridge }) : t('crNnRoleAlone');
            }
            if (g === 'bond') {
                const mode = row.bond_mode || row.ovs_options || '';
                return mode ? crNnT(t, 'crNnRoleBond', { mode }) : t('crNnRoleBondNoMode');
            }
            if (g === 'bridge') return Number(row.bridge_vlan_aware) === 1 || row.bridge_vlan_aware === true ? t('crNnRoleBridgeVlan') : t('crNnRoleBridge');
            const tag = crNnVlanTag(row);
            const parent = crNnVlanParent(row);
            return crNnT(t, 'crNnRoleVlan', { tag: tag || '?', parent: parent || '?' });
        }

        function CrNnPendingBadge({ state }) {
            const { t } = useTranslation();
            if (!state) return null;
            return <span className={`cr-nn-pend cr-nn-pend-${state}`} data-cr-nn-pend={state}>{t(state === 'new' ? 'crNnPendNew' : state === 'removed' ? 'crNnPendRemoved' : 'crNnPendChanged')}</span>;
        }

        function CrNnDiffView({ diff }) {
            const { t } = useTranslation();
            return (
                <pre className="cr-nn-diff" data-cr-nn-diff="" aria-label={t('crNnDiffLabel')}>
                    {diff.lines.map((l, i) => (
                        <span key={i} className={`cr-nn-dl cr-nn-dl-${l.kind}`}>{l.text || ' '}{'\n'}</span>
                    ))}
                </pre>
            );
        }

        // the list of what waits, one line per interface, for the banner and both dialogs
        function CrNnChangeList({ diff, mgmt }) {
            const { t } = useTranslation();
            const names = Object.keys(diff.ifaces).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
            return (
                <ul className="cr-nn-changes" data-cr-nn-changes="">
                    {names.map(n => {
                        const e = diff.ifaces[n];
                        return (
                            <li key={n} data-cr-nn-change={n}>
                                <span className="cr-mono">{n}</span>
                                <CrNnPendingBadge state={e.state} />
                                <span className="cr-muted">{crNnT(t, 'crNnLines', { add: e.add, del: e.del })}</span>
                                {mgmt && mgmt.chain.has(n) && <span className="cr-nn-mgmt-tag" data-cr-nn-mgmt-tag="">{t('crNnMgmtTag')}</span>}
                                {mgmt && !mgmt.chain.has(n) && mgmt.takes && mgmt.takes.has(n) && (
                                    <span className="cr-nn-mgmt-tag" data-cr-nn-mgmt-tag="takes" title={crNnT(t, 'crNnMgmtTakesHint', { takes: mgmt.takes.get(n).join(', ') })}>{t('crNnMgmtTag')}</span>
                                )}
                            </li>
                        );
                    })}
                    {diff.untied > 0 && <li data-cr-nn-change="" className="cr-muted">{crNnT(t, 'crNnUntied', { n: diff.untied })}</li>}
                </ul>
            );
        }

        // the management lines of the Apply dialog
        function CrNnMgmtNote({ mgmt, risk, node }) {
            const { t } = useTranslation();
            const where = [...new Set(mgmt.carriers.map(c => c.iface))];
            const addrs = [...new Set(mgmt.carriers.map(c => c.addr))].join(', ');
            if (risk.level === 'touch') {
                return (
                    <div className="cr-callout cr-callout-error cr-nn-mgmt" role="alert" data-cr-nn-mgmt="touch">
                        <Icons.AlertTriangle className="w-4 h-4" />
                        <div>
                            <p className="cr-strong">{crNnT(t, 'crNnMgmtTouchTitle', { node })}</p>
                            {risk.hits.length > 0 && <p>{crNnT(t, 'crNnMgmtTouchIfaces', { ifaces: risk.hits.join(', '), carrier: where.join(', '), addr: addrs })}</p>}
                            {risk.takers.map(x => (
                                <p key={x.iface} data-cr-nn-taker={x.iface}>{crNnT(t, 'crNnMgmtTouchTakes', { iface: x.iface, takes: x.takes.join(', '), carrier: where.join(', ') })}</p>
                            ))}
                            {risk.named.length > 0 && <p>{crNnT(t, 'crNnMgmtTouchAddr', { addr: risk.named.join(', ') })}</p>}
                        </div>
                    </div>
                );
            }
            const why = [];
            if (risk.reasons.includes('diff')) why.push(t('crNnWhyDiff'));
            if (risk.reasons.includes('untied')) why.push(t('crNnWhyUntied'));
            if (risk.reasons.includes('nodeip')) why.push(t('crNnWhyNodeIp'));
            if (risk.reasons.includes('unmatched')) why.push(crNnT(t, 'crNnWhyUnmatched', { addr: mgmt.lost.map(x => x.addr).join(', ') }));
            if (risk.reasons.includes('hostname')) why.push(crNnT(t, 'crNnWhyHostname', { host: mgmt.hostName }));
            if (risk.level === 'unsure') {
                return (
                    <div className="cr-callout cr-callout-warning cr-nn-mgmt" role="status" data-cr-nn-mgmt="unsure">
                        <Icons.AlertTriangle className="w-4 h-4" />
                        <div>
                            <p className="cr-strong">{t('crNnMgmtUnsureTitle')}</p>
                            {why.map((w, i) => <p key={i}>{w}</p>)}
                        </div>
                    </div>
                );
            }
            return (
                <div className="cr-callout cr-callout-info cr-nn-mgmt" role="status" data-cr-nn-mgmt="clear">
                    <Icons.Info className="w-4 h-4" />
                    <div><p>{where.length ? crNnT(t, 'crNnMgmtClear', { carrier: where.join(', '), addr: addrs }) : t('crNnMgmtNothing')}</p>
                        {why.map((w, i) => <p key={i} className="cr-muted">{w}</p>)}</div>
                </div>
            );
        }

        // listFailed: the interface list was not read, so the dialog cannot tell what Apply touches;
        // Apply stays off until a Retry reads it (onRetry). A change on the path PegaProx uses to reach
        // the node (risk 'touch') is confirmed by typing the node name instead of the checkbox
        function CrNnApplyDialog({ node, diff, diffError, reading, listFailed, listLoading, mgmt, risk, busy, error, readOnly, onCancel, onConfirm, onRetry }) {
            const { t } = useTranslation();
            const [ok, setOk] = useState(false);
            const [typed, setTyped] = useState('');
            const [showDiff, setShowDiff] = useState(false);
            const n = Object.keys(diff.ifaces).length;
            // the confirmation is for what the dialog shows: a new read or another level asks again
            const said = !diff.known ? '' : diff.empty ? '-' : diff.lines.map(l => l.text).join('\n');
            useEffect(() => { setOk(false); setTyped(''); }, [said, risk.level, reading, listFailed]);
            const byName = risk.level === 'touch';
            const confirmed = byName ? typed.trim() === String(node) : ok;
            const locked = busy || readOnly || reading || listFailed;
            return (
                <CrUpdDialog id="nn-apply" title={crNnT(t, 'crNnApplyTitle', { node })} sub={t('crNnApplySub')} busy={busy} onCancel={onCancel}
                    footer={(
                        <>
                            <CrButton onClick={onCancel} disabled={busy}>{t('cancel')}</CrButton>
                            <CrButton variant={risk.level === 'touch' ? 'danger' : 'primary'} onClick={onConfirm}
                                disabled={!confirmed || locked} data-cr-nn-apply-go="">
                                {busy ? t('crNnApplying') : crNnT(t, 'crNnApplyGo', { node })}
                            </CrButton>
                        </>
                    )}>
                    <section className="cr-nn-dsec" data-cr-nn-summary="">
                        <h3 className="cr-nn-dh">{t('crNnWhatChanges')}</h3>
                        {!diff.known && <p className="cr-nn-unknown" data-cr-nn-summary-state="unknown">{crNnT(t, 'crNnSummaryUnknown', { reason: diffError || t('connectionError') })}</p>}
                        {diff.known && diff.empty && <p data-cr-nn-summary-state="none">{t('crNnSummaryNone')}</p>}
                        {diff.known && !diff.empty && (
                            <>
                                <p data-cr-nn-summary-state="some">{crNnT(t, 'crNnSummaryCount', { n, add: diff.added, del: diff.removed })}</p>
                                <CrNnChangeList diff={diff} mgmt={mgmt} />
                                <button type="button" className="cr-nn-link" aria-expanded={showDiff} onClick={() => setShowDiff(v => !v)} data-cr-nn-diff-toggle="">
                                    {showDiff ? t('crNnHideDiff') : t('crNnShowDiff')}
                                </button>
                                {showDiff && <CrNnDiffView diff={diff} />}
                            </>
                        )}
                    </section>
                    <CrNnMgmtNote mgmt={mgmt} risk={risk} node={node} />
                    <div className="cr-callout cr-callout-warning" role="note" data-cr-nn-norollback="">
                        <Icons.AlertCircle className="w-4 h-4" />
                        <div>
                            <p className="cr-strong">{t('crNnNoRollbackTitle')}</p>
                            <p>{crNnT(t, 'crNnNoRollback', { node })}</p>
                        </div>
                    </div>
                    {listFailed && (
                        <div className="cr-callout cr-callout-error" role="alert" data-cr-nn-apply-list="error">
                            <Icons.AlertCircle className="w-4 h-4" />
                            <div>{crNnT(t, 'crNnApplyListFailed', { node })}</div>
                            <button type="button" className="cr-btn cr-btn-xs" onClick={onRetry} disabled={listLoading} data-cr-nn-apply-retry="">{t('retry')}</button>
                        </div>
                    )}
                    {error && <div className="cr-callout cr-callout-error" role="alert" data-cr-nn-error=""><Icons.AlertCircle className="w-4 h-4" /><div>{error}</div></div>}
                    {byName ? (
                        <label className="cr-nn-typename" data-cr-nn-typename="">
                            <span>{crNnT(t, 'crNnApplyTypeName', { node })}</span>
                            <input type="text" className="cr-input cr-nc-mono-input" value={typed} onChange={e => setTyped(e.target.value)} disabled={locked}
                                autoComplete="off" spellCheck={false} data-cr-nn-typename-input="" />
                        </label>
                    ) : (
                        <label className="cr-nn-ack">
                            <input type="checkbox" checked={ok} onChange={e => setOk(e.target.checked)} disabled={locked} data-cr-nn-ack="" />
                            <span>{t('crNnApplyAck')}</span>
                        </label>
                    )}
                </CrUpdDialog>
            );
        }

        function CrNnRevertDialog({ node, diff, diffError, busy, error, readOnly, onCancel, onConfirm }) {
            const { t } = useTranslation();
            return (
                <CrUpdDialog id="nn-revert" title={crNnT(t, 'crNnRevertTitle', { node })} busy={busy} onCancel={onCancel}
                    footer={(
                        <>
                            <CrButton onClick={onCancel} disabled={busy}>{t('cancel')}</CrButton>
                            <CrButton variant="danger" onClick={onConfirm} disabled={busy || readOnly} data-cr-nn-revert-go="">
                                {busy ? t('crNnReverting') : t('crNnRevertGo')}
                            </CrButton>
                        </>
                    )}>
                    <section className="cr-nn-dsec" data-cr-nn-summary="">
                        <h3 className="cr-nn-dh">{t('crNnWhatDiscarded')}</h3>
                        {!diff.known && <p className="cr-nn-unknown" data-cr-nn-summary-state="unknown">{crNnT(t, 'crNnRevertUnknown', { reason: diffError || t('connectionError') })}</p>}
                        {diff.known && diff.empty && <p data-cr-nn-summary-state="none">{t('crNnRevertNone')}</p>}
                        {diff.known && !diff.empty && <CrNnChangeList diff={diff} />}
                    </section>
                    <p className="cr-nn-plain">{t('crNnRevertPlain')}</p>
                    {error && <div className="cr-callout cr-callout-error" role="alert" data-cr-nn-error=""><Icons.AlertCircle className="w-4 h-4" /><div>{error}</div></div>}
                </CrUpdDialog>
            );
        }

        async function crNnError(res, t) {
            if (!res) return t('connectionError');
            let body = null;
            try { body = await res.json(); } catch (_) { body = null; }
            const said = body && (body.error || body.message);
            return said ? `${said} (HTTP ${res.status})` : `HTTP ${res.status}`;
        }

        // network: the list as loadTabData keeps it (undefined while not read, null when the read failed)
        function CrNodeNetwork({ network, loading, clusterId, node, nodeIp, nodeIpSource, clusterHost, authFetch, addToast, readOnly,
                                 onReload, onEdit, onCreate, onDelete }) {
            const { t } = useTranslation();
            const [changes, setChanges] = useState({ state: 'idle' });
            const [dialog, setDialog] = useState(null);   // 'apply' | 'revert'
            const [busy, setBusy] = useState(false);
            const [error, setError] = useState('');
            const [showDiff, setShowDiff] = useState(false);
            const [menu, setMenu] = useState(false);
            const seq = useRef(0);
            const base = `${API_URL}/clusters/${clusterId}/nodes/${node}/network`;

            const readChanges = () => {
                const my = ++seq.current;
                setChanges(c => ({ ...c, state: 'loading' }));
                authFetch(`${base}/changes`).then(async res => {
                    if (my !== seq.current) return;
                    if (res && res.ok) {
                        let body = null;
                        try { body = await res.json(); } catch (_) { body = null; }
                        if (my !== seq.current) return;
                        if (body && typeof body.changes === 'string') setChanges({ state: 'ok', text: body.changes });
                        else setChanges({ state: 'error', error: t('crNnBadAnswer') });
                        return;
                    }
                    const why = await crNnError(res, t);
                    if (my === seq.current) setChanges({ state: 'error', error: why });
                });
            };
            // every new read of the list reads what waits again; the node switch resets the list first
            useEffect(() => {
                if (Array.isArray(network)) readChanges();
                else { seq.current++; setChanges({ state: 'idle' }); }
            }, [network, clusterId, node]);
            useEffect(() => { setDialog(null); setShowDiff(false); setError(''); }, [clusterId, node]);
            useEffect(() => {
                if (!menu) return undefined;
                const close = () => setMenu(false);
                document.addEventListener('click', close);
                return () => document.removeEventListener('click', close);
            }, [menu]);

            const model = useMemo(() => crNnModel(network), [network]);
            const diff = useMemo(() => crNnParseDiff(changes.state === 'ok' ? changes.text : undefined), [changes]);
            const mgmt = useMemo(() => crNnManagement(model, { nodeIp, nodeIpStandIn: /_fallback$/.test(nodeIpSource || ''), clusterHost }),
                                 [model, nodeIp, nodeIpSource, clusterHost]);
            const risk = useMemo(() => crNnRisk(mgmt, diff), [mgmt, diff]);
            const waiting = Object.keys(diff.ifaces);
            const removed = waiting.filter(n => diff.ifaces[n].state === 'removed' && !model.byName.has(n)).sort();

            const run = async (method) => {
                setBusy(true);
                setError('');
                const res = await authFetch(base, { method });
                if (res && res.ok) {
                    setBusy(false);
                    setDialog(null);
                    addToast(method === 'PUT' ? t('crNnApplied') : t('crNnReverted'), 'success');
                    onReload();
                    // the reload of the node runs as a task; read once more when it has had time
                    if (method === 'PUT') setTimeout(() => onReload(), 4000);
                    return;
                }
                const why = await crNnError(res, t);
                setBusy(false);
                setError(why);
            };

            const marks = (name) => {
                const row = model.byName.get(name);
                const e = diff.ifaces[name];
                const mg = mgmt.chain.has(name);
                return {
                    group: row ? crNnGroup(row) : 'missing', pending: !!e, mgmt: mg, missing: !row,
                    title: [row ? '' : t('crNnNotListed'), e ? t(e.state === 'new' ? 'crNnPendNew' : e.state === 'removed' ? 'crNnPendRemoved' : 'crNnPendChanged') : '',
                            mg ? t('crNnMgmtTag') : ''].filter(Boolean).join(' - ') || undefined,
                };
            };

            const listState = network === undefined ? (loading ? 'loading' : 'idle') : network === null ? 'error' : model.list.length ? 'ok' : 'empty';
            const groupLabel = { physical: t('crNnGroupPhysical'), bond: t('crNnGroupBond'), bridge: t('crNnGroupBridge'), vlan: t('crNnGroupVlan'), other: t('crNnGroupOther') };

            const pendingBanner = () => {
                if (listState !== 'ok' && listState !== 'empty') return null;
                if (changes.state === 'loading' || changes.state === 'idle') {
                    return <div className="cr-callout cr-callout-info" role="status" data-cr-nn-pending="loading"><Icons.RotateCw className="w-4 h-4" /><div>{t('crNnReadingChanges')}</div></div>;
                }
                if (changes.state === 'error') {
                    return (
                        <div className="cr-callout cr-callout-warning" role="alert" data-cr-nn-pending="error">
                            <Icons.AlertTriangle className="w-4 h-4" />
                            <div><p>{crNnT(t, 'crNnChangesFailed', { reason: changes.error })}</p></div>
                            <button type="button" className="cr-btn cr-btn-xs" onClick={readChanges}>{t('retry')}</button>
                        </div>
                    );
                }
                if (diff.empty) return <div className="cr-callout cr-callout-info" role="status" data-cr-nn-pending="none"><Icons.Check className="w-4 h-4" /><div>{t('crNnNothingWaits')}</div></div>;
                return (
                    <div className="cr-callout cr-callout-warning" role="status" data-cr-nn-pending="some">
                        <Icons.AlertTriangle className="w-4 h-4" />
                        <div className="cr-nn-pending-body">
                            <p className="cr-strong">{crNnT(t, 'crNnWaitingTitle', { n: waiting.length })}</p>
                            <CrNnChangeList diff={diff} mgmt={mgmt} />
                            <button type="button" className="cr-nn-link" aria-expanded={showDiff} onClick={() => setShowDiff(v => !v)} data-cr-nn-diff-toggle="">
                                {showDiff ? t('crNnHideDiff') : t('crNnShowDiff')}
                            </button>
                            {showDiff && <CrNnDiffView diff={diff} />}
                        </div>
                    </div>
                );
            };

            const mgmtLine = () => {
                if (listState !== 'ok') return null;
                const parts = mgmt.carriers.map(c => {
                    const below = [...crNnBelow(model, c.iface)];
                    return crNnT(t, c.role === 'api' ? 'crNnMgmtApi' : c.role === 'both' ? 'crNnMgmtBoth' : 'crNnMgmtNode',
                                 { addr: c.addr, iface: c.iface, below: below.length ? ` (${below.join(', ')})` : '' });
                });
                for (const x of mgmt.unmatched) parts.push(crNnT(t, x.role === 'api' ? 'crNnMgmtApiElsewhere' : 'crNnMgmtUnmatched', { addr: x.addr }));
                if (mgmt.hostName) parts.push(crNnT(t, 'crNnMgmtHostname', { host: mgmt.hostName }));
                if (mgmt.nodeUnknown) parts.push(t('crNnMgmtNodeUnknown'));
                if (!parts.length) return null;
                return <p className="cr-nn-mgmt-line" data-cr-nn-mgmt-line="">{parts.map((p, i) => <span key={i}>{p}</span>)}</p>;
            };

            return (
                <CrNcSection id="network" data-cr-nn="" title={t('network')} desc={t('crNcNetDesc')}
                    badge={(
                        <>
                            {listState === 'ok' && <span className="cr-muted cr-nn-count">{crNnT(t, 'crNnCount', { n: model.list.length })}</span>}
                            {changes.state === 'ok' && waiting.length > 0 && <CrBadge tone="warning">{crNnT(t, 'crNnWaitingBadge', { n: waiting.length })}</CrBadge>}
                        </>
                    )}
                    actions={(
                        <>
                            <div className="cr-nn-menu-wrap">
                                <CrButton icon={<Icons.Plus />} onClick={e => { e.stopPropagation(); setMenu(v => !v); }} aria-haspopup="menu" aria-expanded={menu} data-cr-nn-create="">
                                    {t('crNnCreate')} <Icons.ChevronDown className="w-3 h-3" />
                                </CrButton>
                                {menu && (
                                    <div className="cr-nn-menu" role="menu">
                                        {CR_NN_CREATE.map(([ty, label]) => (
                                            <button key={ty} type="button" role="menuitem" onClick={() => { setMenu(false); onCreate(ty); }} data-cr-nn-create-type={ty}>{label}</button>
                                        ))}
                                    </div>
                                )}
                            </div>
                            <span className="cr-nc-acts-sep" aria-hidden="true" />
                            <CrButton variant="danger" onClick={() => { setError(''); setDialog('revert'); }} disabled={listState === 'loading'} data-cr-nn-revert="">{t('crNnRevert')}</CrButton>
                            <CrButton variant="primary" onClick={() => { setError(''); setDialog('apply'); }} disabled={listState === 'loading'} data-cr-nn-apply="">{t('crNnApply')}</CrButton>
                        </>
                    )}>
                    {pendingBanner()}
                    {mgmtLine()}
                    {listState === 'loading' && <div className="cr-nn-state" role="status" data-cr-nn-list="loading"><Icons.RotateCw className="w-4 h-4 animate-spin" /> {t('crNnReadingList')}</div>}
                    {listState === 'error' && (
                        <div className="cr-callout cr-callout-error" role="alert" data-cr-nn-list="error">
                            <Icons.AlertCircle className="w-4 h-4" />
                            <div>{crNnT(t, 'crNnListFailed', { node })}</div>
                            <button type="button" className="cr-btn cr-btn-xs" onClick={onReload}>{t('retry')}</button>
                        </div>
                    )}
                    {listState === 'empty' && <div className="cr-callout cr-callout-warning" role="status" data-cr-nn-list="empty"><Icons.AlertTriangle className="w-4 h-4" /><div>{t('crNnListEmpty')}</div></div>}
                    {listState === 'ok' && model.tops.length > 0 && (
                        <section className="cr-nn-deps" data-cr-nn-deps="">
                            <h4 className="cr-nn-sub">{t('crNnDeps')}</h4>
                            {model.tops.map(n => <CrNnChainView key={n} model={model} name={n} marks={marks} />)}
                        </section>
                    )}
                    {listState === 'ok' && (
                        <div className="cr-nn-scroll">
                            <table className="corp-datagrid cr-table cr-nn-table" aria-label={t('network')}>
                                <thead>
                                    <tr>
                                        <th>{t('name')}</th><th>{t('crNnRole')}</th><th>{t('crNnBuiltFrom')}</th><th>{t('crNnAddress')}</th>
                                        <th>{t('crNnState')}</th><th>{t('comment')}</th><th aria-label={t('actions')}></th>
                                    </tr>
                                </thead>
                                {CR_NN_GROUPS.filter(g => model.groups[g].length).map(g => (
                                    <tbody key={g} data-cr-nn-group={g}>
                                        <tr className="cr-nn-grow"><th colSpan={7} scope="rowgroup">{groupLabel[g]} <span className="cr-muted">{model.groups[g].length}</span></th></tr>
                                        {model.groups[g].map(row => {
                                            const name = String(row.iface);
                                            const e = diff.ifaces[name];
                                            const below = model.lower.get(name) || [];
                                            const up = model.upper.get(name) || [];
                                            const addr = [row.cidr || row.address, row.cidr6 || row.address6].filter(Boolean);
                                            const gw = [row.gateway, row.gateway6].filter(Boolean);
                                            return (
                                                <tr key={name} data-cr-nn-row={name} className={e ? 'cr-nn-row-pending' : ''}>
                                                    <td className="cr-nn-namecell">
                                                        <span className="cr-mono cr-nn-name">{name}</span>
                                                        {(e || mgmt.chain.has(name)) && (
                                                            <span className="cr-nn-marks">
                                                                {e && <CrNnPendingBadge state={e.state} />}
                                                                {mgmt.chain.has(name) && <span className="cr-nn-mgmt-tag" data-cr-nn-mgmt-tag="" title={t('crNnMgmtTagHint')}>{t('crNnMgmtTag')}</span>}
                                                            </span>
                                                        )}
                                                    </td>
                                                    <td>{crNnRole(t, model, row)}</td>
                                                    <td className="cr-nn-rel">
                                                        {below.length > 0 && <span>{crNnT(t, 'crNnFrom', { list: below.join(', ') })}</span>}
                                                        {up.length > 0 && <span className="cr-muted">{crNnT(t, 'crNnUsedBy', { list: up.slice().sort().join(', ') })}</span>}
                                                        {!below.length && !up.length && <span className="cr-muted">-</span>}
                                                    </td>
                                                    <td className="cr-nn-addr">
                                                        {addr.map(a => <span key={a} className="cr-mono">{a}</span>)}
                                                        {gw.map(a => <span key={a} className="cr-muted">{crNnT(t, 'crNnVia', { gw: a })}</span>)}
                                                        {!addr.length && !gw.length && <span className="cr-muted">-</span>}
                                                    </td>
                                                    <td>{row.active ? <CrBadge tone="success">{t('crNnActive')}</CrBadge> : <CrBadge tone="neutral">{t('crNnInactive')}</CrBadge>}</td>
                                                    <td className="cr-nn-comment" title={row.comments || ''}>{row.comments || ''}</td>
                                                    <td className="cr-nn-rowacts"><div className="cr-nn-rowbtns">
                                                        <button type="button" className="cr-icon-btn" title={t('edit')} aria-label={`${t('edit')} ${name}`} onClick={() => onEdit(row)} data-cr-nn-edit={name}><span className="cr-ico" aria-hidden="true"><Icons.Cog /></span></button>
                                                        <button type="button" className="cr-icon-btn cr-nc-danger-ico" title={t('delete')} aria-label={`${t('delete')} ${name}`} onClick={() => onDelete(row)} data-cr-nn-delete={name}><span className="cr-ico" aria-hidden="true"><Icons.Trash /></span></button>
                                                    </div></td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                ))}
                                {removed.length > 0 && (
                                    <tbody data-cr-nn-group="removed">
                                        <tr className="cr-nn-grow"><th colSpan={7} scope="rowgroup">{t('crNnGroupRemoved')} <span className="cr-muted">{removed.length}</span></th></tr>
                                        {removed.map(n => (
                                            <tr key={n} data-cr-nn-row={n} className="cr-nn-row-pending">
                                                <td className="cr-nn-namecell"><span className="cr-mono cr-nn-name">{n}</span><span className="cr-nn-marks"><CrNnPendingBadge state="removed" /></span></td>
                                                <td colSpan={6} className="cr-muted">{t('crNnRemovedHint')}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                )}
                            </table>
                        </div>
                    )}
                    {dialog === 'apply' && (
                        <CrNnApplyDialog node={node} diff={diff} diffError={changes.state === 'error' ? changes.error : changes.state === 'ok' ? ''
                                : network === null ? t('crNnListNotRead') : t('crNnReadingChanges')}
                            reading={changes.state === 'loading' || (changes.state === 'idle' && network !== null)} mgmt={mgmt} risk={risk} busy={busy} error={error} readOnly={readOnly}
                            listFailed={network === null} listLoading={loading} onRetry={onReload}
                            onCancel={() => { if (!busy) setDialog(null); }} onConfirm={() => run('PUT')} />
                    )}
                    {dialog === 'revert' && (
                        <CrNnRevertDialog node={node} diff={diff} diffError={changes.state === 'error' ? changes.error : (changes.state === 'ok' ? '' : t('crNnReadingChanges'))}
                            busy={busy} error={error} readOnly={readOnly}
                            onCancel={() => { if (!busy) setDialog(null); }} onConfirm={() => run('DELETE')} />
                    )}
                </CrNcSection>
            );
        }

        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned (Preview): hardware health and disks of a node - LW Nov 2026
        // Hardware: the lm-sensors rows (GET .../sensors) and the rows of the in-band monitoring
        // (HardwareMonitoringPanel reads GET .../hardware and hands them up) by kind, with value, Max
        // and Critical where a row carries them and a state worked out from those alone. A sensor
        // without a value, with a value that is not a number or without any limit is never normal.
        // Disks: disks/list joined with the LVM tree, the thin pools and the Ceph OSD ids; the SMART
        // answers and the ZFS pool members are read on request (one request per disk or pool, three
        // at a time), never on open. A value nobody reported says so, in a neutral style.
        // ═══════════════════════════════════════════════════════════

        // an answer as the preview keeps it: the body, or { __crFail } with why the read failed
        // (loadTabData hands the classic views null for any failure and the reason is gone)
        async function crNdRead(r) {
            if (!r) return { __crFail: { status: 0, error: '', code: 'NO_ANSWER' } };
            let body;
            try { body = await r.json(); } catch (e) { body = undefined; }
            if (!r.ok) {
                const b = body && typeof body === 'object' ? body : {};
                return { __crFail: { status: r.status, error: typeof b.error === 'string' ? b.error : '',
                                     code: typeof b.code === 'string' ? b.code : '' } };
            }
            if (body === undefined) return { __crFail: { status: r.status, error: '', code: 'NOT_JSON' } };
            return body;
        }
        const crNdFail = (x) => (x && typeof x === 'object' && !Array.isArray(x) && x.__crFail) || null;

        function crNdWhy(t, f) {
            if (!f) return '';
            if (f.error) return f.error;
            if (f.code === 'NOT_JSON') return t('crNdNotJson');
            if (f.code === 'NO_ANSWER' || !f.status) return t('crNdNoAnswer');
            return `HTTP ${f.status}`;
        }

        const crNhNum = (v) => typeof v === 'number' && Number.isFinite(v);
        const CR_NH_KINDS = ['temp', 'fan', 'psu', 'volt', 'other'];
        // a power supply by its name only; the name never gives it a state
        const CR_NH_PSU = /(^|[^a-z])(psu|ps ?\d|power ?supply|pwr ?supply)/i;
        // how bad a state is, for the summary: 3 critical, 2 warning, 1 normal, 0 no state
        const CR_NH_RANK = { critical: 3, alarm: 3, high: 2, warning: 2, normal: 1 };

        const crNhLimit = (v) => (v == null || v === '' ? { k: 'none' } : crNhNum(v) ? { k: 'num', v } : { k: 'bad', raw: String(v) });

        // one lm-sensors row (get_node_sensors): the state comes from its own Max and Critical and
        // the chip's alarm flag. alarm is false wherever the chip has no alarm file, so false alone
        // never makes a row normal: that takes a limit the value is below. The answer has no lower
        // limit, so only a temperature can be normal below the top; a fan or a rail below Max is
        // said as just that (a stopped fan or a dead rail is below Max too)
        const CR_NH_TEMP_FLOOR = -40;   // a reading below this is a sensor error code (-127, -128, -273), not a temperature
        function crNhLmRow(s) {
            s = s && typeof s === 'object' ? s : {};
            const kind = s.kind === 'temp' || s.kind === 'fan' || s.kind === 'volt' ? s.kind : 'other';
            const unit = kind === 'temp' ? '°C' : kind === 'fan' ? 'RPM' : kind === 'volt' ? 'V' : '';
            const max = crNhLimit(s.max), crit = crNhLimit(s.crit);
            let value, state;
            if (s.value == null || s.value === '') { value = { k: 'none' }; state = 'none'; }
            else if (!crNhNum(s.value)) { value = { k: 'bad', raw: String(s.value) }; state = 'bad'; }
            else {
                value = { k: 'num', v: s.value };
                if (crit.k === 'num' && s.value >= crit.v) state = 'critical';
                else if (s.alarm === true) state = 'alarm';
                else if (max.k === 'num' && s.value >= max.v) state = 'high';
                else if (kind === 'fan' && s.value === 0) state = 'zero';
                else if (kind === 'temp' && s.value < CR_NH_TEMP_FLOOR) state = 'implausible';
                else if (max.k !== 'num' && crit.k !== 'num') state = 'nolimit';
                else state = kind === 'temp' ? 'normal' : 'belowmax';
            }
            return { src: 'lm', group: kind, name: String(s.label || ''), where: String(s.chip || ''), unit, value, max, crit, state };
        }

        // one row of the in-band monitoring (bmc.parse_sensors, redfish): no limits in the answer, the
        // state is what the controller says (ok, warning, critical, na); nothing read is never normal
        function crNhBmcRow(s) {
            s = s && typeof s === 'object' ? s : {};
            const name = String(s.name || '');
            const k = String(s.kind || '');
            const numeric = ['temp', 'fan', 'volt', 'power', 'current'].includes(k);
            const group = CR_NH_PSU.test(name) || k === 'power' || k === 'current' ? 'psu'
                : (k === 'temp' || k === 'fan' || k === 'volt') ? k : 'other';
            const reading = typeof s.reading === 'string' ? s.reading.trim() : '';
            const st = String(s.status == null ? '' : s.status).trim().toLowerCase();
            let state = st === 'ok' ? 'normal' : st === 'warning' ? 'warning' : st === 'critical' ? 'critical'
                : (st === '' || st === 'na') ? 'none' : 'raw';
            let value = crNhNum(s.value) ? { k: 'num', v: s.value } : reading ? { k: 'text', raw: reading } : { k: 'none' };
            if (value.k === 'none') { if (state === 'normal' || state === 'raw') state = 'none'; }
            else if (numeric && value.k === 'text' && state !== 'none') {
                // a measuring sensor that sent text instead of a number
                value = { k: 'bad', raw: reading };
                if (state === 'normal' || state === 'raw') state = 'bad';
            }
            return { src: 'bmc', group, name, where: 'BMC', unit: typeof s.unit === 'string' ? s.unit : '', value,
                     max: { k: 'none' }, crit: { k: 'none' }, state, raw: state === 'raw' ? st : '' };
        }

        // what the lm-sensors read gave: loading, error (with why), empty (lm-sensors ran, found nothing) or ok
        function crNhLmState(read) {
            if (read === undefined) return { state: 'loading', rows: [] };
            const f = crNdFail(read);
            if (f) return { state: 'error', fail: f, rows: [] };
            if (!read || typeof read !== 'object' || !Array.isArray(read.sensors)) {
                return { state: 'error', fail: { status: 200, error: (read && typeof read.error === 'string') ? read.error : '', code: 'NOT_JSON' }, rows: [] };
            }
            if (!read.sensors.length) return { state: 'empty', rows: [] };
            return { state: 'ok', rows: read.sensors.map(crNhLmRow), source: read.source === 'text' || read.source === 'hwmon' ? read.source : 'json' };
        }

        // what the in-band panel handed up: loading, unknown (setting not readable), off, error, unavailable or ok
        function crNhBmcState(bmc, node) {
            if (!bmc || bmc.node !== node || bmc.loading) return { state: 'loading', rows: [] };
            if (bmc.consent === null) return { state: 'unknown', rows: [] };
            if (bmc.consent === false || !bmc.hw) return { state: 'off', rows: [] };
            const hw = bmc.hw;
            if (hw.error) return { state: 'error', why: String(hw.error), rows: [] };
            if (hw.available !== true) return { state: 'unavailable', why: String(hw.reason || ''), rows: [] };
            const rows = Array.isArray(hw.sensors) ? hw.sensors.map(crNhBmcRow) : [];
            const health = ['ok', 'warning', 'critical'].includes(hw.health) ? hw.health : '';
            const reasons = Array.isArray(hw.health_reasons) ? hw.health_reasons.map(r => String((r && r.label) || '')).filter(Boolean) : [];
            return { state: 'ok', rows, health, reasons };
        }

        function crNhModel(read, bmc, node) {
            const lm = crNhLmState(read);
            const inband = crNhBmcState(bmc, node);
            const rows = [...lm.rows, ...inband.rows];
            const groups = {};
            for (const g of CR_NH_KINDS) groups[g] = [];
            for (const r of rows) groups[r.group].push(r);
            const counts = { critical: 0, warning: 0, normal: 0, none: 0 };
            let worst = 0;
            for (const r of rows) {
                const k = CR_NH_RANK[r.state] || 0;
                worst = Math.max(worst, k);
                counts[k === 3 ? 'critical' : k === 2 ? 'warning' : k === 1 ? 'normal' : 'none']++;
            }
            if (inband.health === 'critical') worst = Math.max(worst, 3);
            else if (inband.health === 'warning') worst = Math.max(worst, 2);
            const overall = worst === 3 ? 'critical' : worst === 2 ? 'warning' : worst === 1 ? 'normal' : 'none';
            return { lm, inband, rows, groups, counts, overall };
        }

        // the stored temperature points (load_node_temps: ISO times of the 5-minute snapshots)
        function crNhTime(v) {
            if (crNhNum(v)) return v > 1e12 ? v / 1000 : v;
            if (typeof v !== 'string' || !v.trim()) return null;
            const ms = Date.parse(v.trim().replace(/(\.\d{3})\d+/, '$1'));
            return Number.isFinite(ms) ? ms / 1000 : null;
        }
        function crNhTemps(read) {
            if (read === undefined) return { state: 'loading' };
            const f = crNdFail(read);
            if (f) return { state: 'error', fail: f };
            if (!read || !Array.isArray(read.series)) return { state: 'error', fail: { status: 200, error: '', code: 'NOT_JSON' } };
            const pts = [];
            let skipped = 0;
            for (const p of read.series) {
                const sec = crNhTime(p && p.ts);
                if (sec == null || !crNhNum(p.temp)) { skipped++; continue; }
                pts.push([sec, p.temp]);
            }
            pts.sort((a, b) => a[0] - b[0]);
            if (!pts.length) return { state: 'empty', skipped };
            const vals = pts.map(p => p[1]);
            return { state: 'ok', ts: pts.map(p => p[0]), vals, skipped, min: Math.min(...vals), max: Math.max(...vals), last: vals[vals.length - 1],
                     avg: vals.reduce((a, b) => a + b, 0) / vals.length };
        }

        // --- disks ------------------------------------------------------------------------------

        const crNdDev = (p) => String(p || '').replace(/^\/dev\//, '');

        // whether a name from the LVM tree or a ZFS vdev is this disk or one of its partitions:
        // /dev/sda3, sda3, nvme0n1p3, the by-id link of the disk (with -partN) or its wwn link
        function crNdOwns(disk, name) {
            const dev = crNdDev(disk && disk.devpath);
            if (!dev || !name) return false;
            const base = String(name).trim().replace(/^\/dev\/(disk\/by(?:-[a-z]+)\/)?/, '');
            if (!base) return false;
            if (base === dev) return true;
            // sda3 under sda, nvme0n1p3 under nvme0n1 (a name that ends in a digit takes a p first)
            if (base.startsWith(dev) && (/\d$/.test(dev) ? /^p\d+$/ : /^\d+$/).test(base.slice(dev.length))) return true;
            const ids = [];
            if (disk.by_id_link) ids.push(String(disk.by_id_link).replace(/^.*\//, ''));
            if (disk.wwn && disk.wwn !== 'unknown') ids.push('wwn-' + String(disk.wwn));
            return ids.some(id => id && (base === id || (base.startsWith(id + '-part') && /^\d+$/.test(base.slice(id.length + 5)))));
        }

        // the health disks/list carries (smartctl -H through Proxmox VE)
        function crNdHealth(h) {
            const raw = h == null ? '' : String(h).trim();
            const up = raw.toUpperCase();
            if (!raw || up === 'UNKNOWN') return { state: 'none', text: '' };
            if (up === 'PASSED' || up === 'OK') return { state: 'ok', text: raw };
            if (up.startsWith('FAIL')) return { state: 'failed', text: raw };
            if (up === 'SMART DISABLED') return { state: 'off', text: raw };
            return { state: 'other', text: raw };
        }

        // wearout of disks/list is what is LEFT (100 - Percentage Used for NVMe, the normalized
        // wear attribute for SATA); 'N/A' where Proxmox VE has none
        function crNdWear(w) {
            if (w == null || w === '' || (typeof w === 'string' && /^n\/?a$/i.test(w.trim()))) return { state: 'none' };
            const n = typeof w === 'number' ? w : (/^\s*\d+(\.\d+)?\s*$/.test(String(w)) ? parseFloat(w) : NaN);
            if (!Number.isFinite(n) || n < 0 || n > 100) return { state: 'bad', raw: String(w) };
            return { state: 'ok', left: n, used: Math.round((100 - n) * 10) / 10 };
        }

        const crNdInt = (raw) => {
            const m = /^\s*(-?\d[\d,]*)/.exec(String(raw == null ? '' : raw));
            return m ? parseInt(m[1].replace(/,/g, ''), 10) : null;
        };

        // what a SMART answer (disks/<dev>/smart) says: temperature, error counters, attributes at or
        // below their threshold, NVMe wear and critical warning. {} is what a failed read gives too
        const CR_ND_ATA_ERR = [[5, 'crNdErrRealloc', true], [187, 'crNdErrUncorrect', true], [197, 'crNdErrPending', true],
                               [198, 'crNdErrOffline', true], [199, 'crNdErrCrc', false]];
        function crNdSmart(ans) {
            const out = { known: false, temp: { k: 'none' }, errors: [], failing: [], wearUsed: null, critWarn: null };
            if (!ans || typeof ans !== 'object') return out;
            const attrs = Array.isArray(ans.attributes) ? ans.attributes : [];
            const text = typeof ans.text === 'string' ? ans.text : '';
            out.known = !!(attrs.length || text.trim());
            if (attrs.length) {
                const byId = new Map();
                for (const a of attrs) {
                    if (!a || typeof a !== 'object') continue;
                    const id = parseInt(String(a.id == null ? '' : a.id).trim(), 10);
                    if (Number.isFinite(id) && !byId.has(id)) byId.set(id, a);
                    const thr = crNhNum(a.threshold) ? a.threshold : null;
                    const val = crNhNum(a.normalized) ? a.normalized : crNhNum(a.value) ? a.value : null;
                    const fail = typeof a.fail === 'string' ? a.fail.trim() : '';
                    if ((thr != null && thr > 0 && val != null && val <= thr) || (fail && fail !== '-')) out.failing.push(String(a.name || id));
                }
                const ta = byId.get(194) || byId.get(190);
                if (ta) {
                    const n = crNdInt(ta.raw);
                    out.temp = n == null ? { k: 'bad', raw: String(ta.raw == null ? '' : ta.raw) } : { k: 'num', v: n };
                }
                for (const [id, key, hard] of CR_ND_ATA_ERR) {
                    const a = byId.get(id);
                    if (!a) continue;
                    const n = crNdInt(a.raw);
                    out.errors.push(n == null ? { key, bad: String(a.raw == null ? '' : a.raw), hard } : { key, n, hard });
                }
            }
            if (text) {
                const line = (re) => { const m = re.exec(text); return m ? m[1].trim() : null; };
                const tv = line(/^\s*Temperature:\s*(.*?)\s*(?:Celsius)?\s*$/mi) ?? line(/^\s*Current Drive Temperature:\s*(.*?)\s*(?:C)?\s*$/mi);
                if (tv != null) {
                    const n = /^-?\d+$/.test(tv) ? parseInt(tv, 10) : null;
                    out.temp = n == null ? { k: 'bad', raw: tv } : { k: 'num', v: n };
                }
                const count = (re, key, hard) => {
                    const v = line(re);
                    if (v == null) return;
                    const n = /^\d[\d,]*$/.test(v) ? parseInt(v.replace(/,/g, ''), 10) : null;
                    out.errors.push(n == null ? { key, bad: v, hard } : { key, n, hard });
                };
                count(/^\s*Media and Data Integrity Errors:\s*(.*)$/mi, 'crNdErrMedia', true);
                count(/^\s*Error Information Log Entries:\s*(.*)$/mi, 'crNdErrLog', false);
                count(/^\s*Elements in grown defect list:\s*(.*)$/mi, 'crNdErrGrown', true);
                for (const [re, key] of [[/^\s*read:\s+(.*)$/mi, 'crNdErrSasRead'], [/^\s*write:\s+(.*)$/mi, 'crNdErrSasWrite']]) {
                    const v = line(re);
                    if (v == null) continue;
                    const last = v.split(/\s+/).pop();
                    const n = /^\d+$/.test(last) ? parseInt(last, 10) : null;
                    out.errors.push(n == null ? { key, bad: v, hard: true } : { key, n, hard: true });
                }
                const pu = line(/^\s*Percentage Used(?: endurance indicator)?:\s*(.*)$/mi);
                if (pu != null && /^\d+(\.\d+)?\s*%$/.test(pu)) out.wearUsed = parseFloat(pu);
                const cw = line(/^\s*Critical Warning:\s*(.*)$/mi);
                if (cw != null) out.critWarn = /^0x0+$/i.test(cw) ? 0 : (/^0x[0-9a-f]+$/i.test(cw) ? parseInt(cw, 16) : cw);
            }
            return out;
        }

        // the leaves of a ZFS pool (zpool.pool_detail 'vdevs': rows with children)
        function crNdZfsLeaves(detail) {
            const out = [];
            const walk = (rows, depth) => {
                for (const r of Array.isArray(rows) ? rows : []) {
                    if (!r || typeof r !== 'object' || depth > 8) continue;
                    if (Array.isArray(r.children) && r.children.length) walk(r.children, depth + 1);
                    else out.push(r);
                }
            };
            walk(detail && detail.vdevs, 0);
            return out;
        }

        // the volume groups of the disks/lvm tree (PVE answers {children: [vg {children: [pv]}]})
        function crNdVgs(lvm) {
            const list = Array.isArray(lvm) ? lvm : (lvm && Array.isArray(lvm.children) ? lvm.children : []);
            return list.filter(v => v && typeof v === 'object').map(v => ({
                name: String(v.name || v.vg || ''),
                pvs: (Array.isArray(v.children) ? v.children : []).map(p => String((p && p.name) || '')).filter(Boolean),
            })).filter(v => v.name);
        }

        // read: [disks, lvm, lvmthin, zfs] as loadTabData kept them; zfs: {pool: {state, detail|fail}}
        function crNdModel(read, zfs) {
            if (!Array.isArray(read)) return { state: 'loading', rows: [] };
            const [dl, lvm, thin, pools] = read;
            const f = crNdFail(dl);
            if (f) return { state: 'error', fail: f, rows: [] };
            if (!Array.isArray(dl)) return { state: 'error', fail: { status: 200, error: '', code: 'NOT_JSON' }, rows: [] };
            const side = {
                lvm: crNdFail(lvm), thin: crNdFail(thin), zfs: crNdFail(pools),
            };
            const vgs = side.lvm ? [] : crNdVgs(lvm);
            const thins = side.thin || !Array.isArray(thin) ? [] : thin.filter(x => x && typeof x === 'object');
            const zpools = side.zfs || !Array.isArray(pools) ? [] : pools.map(p => String((p && p.name) || '')).filter(Boolean);
            const rows = dl.filter(d => d && typeof d === 'object').map(d => {
                const uses = [];
                for (const vg of vgs) {
                    if (vg.pvs.some(pv => crNdOwns(d, pv))) {
                        uses.push({ kind: 'lvm', name: vg.name, thin: thins.filter(x => String(x.vg || '') === vg.name).map(x => String(x.lv || '')).filter(Boolean) });
                    }
                }
                const osds = Array.isArray(d['osdid-list']) && d['osdid-list'].length ? d['osdid-list']
                    : (d.osdid != null && String(d.osdid) !== '-1' && String(d.osdid) !== '' ? [d.osdid] : []);
                for (const o of osds) uses.push({ kind: 'ceph', name: String(o) });
                let zfsState = '';
                for (const pool of zpools) {
                    const z = zfs && zfs[pool];
                    if (!z || z.state !== 'ok') continue;
                    for (const leaf of crNdZfsLeaves(z.detail)) {
                        if (crNdOwns(d, leaf.name)) uses.push({ kind: 'zfs', name: pool, vstate: String(leaf.state || ''), read: leaf.read, write: leaf.write, cksum: leaf.cksum });
                    }
                }
                const usedText = typeof d.used === 'string' ? d.used.trim() : '';
                if (/zfs/i.test(usedText) && !uses.some(u => u.kind === 'zfs')) {
                    const any = zpools.map(p => zfs && zfs[p]).filter(Boolean);
                    zfsState = !zpools.length ? 'nopool' : any.length < zpools.length || any.some(z => z.state === 'reading') ? 'unread'
                        : any.some(z => z.state !== 'ok') ? 'failed' : 'nomatch';
                }
                return {
                    disk: d, dev: crNdDev(d.devpath), type: String(d.type || '').toLowerCase(), size: d.size,
                    health: crNdHealth(d.health), wear: crNdWear(d.wearout), uses, usedText, zfsState,
                };
            });
            return { state: rows.length ? 'ok' : 'empty', rows, side, zpools };
        }

        window.PegaProxNodeHw = Object.freeze({ lmRow: crNhLmRow, bmcRow: crNhBmcRow, model: crNhModel, temps: crNhTemps,
                                                owns: crNdOwns, health: crNdHealth, wear: crNdWear, smart: crNdSmart, disks: crNdModel });

        // --- the hardware tab --------------------------------------------------------------------

        const CR_NH_STATES = {
            critical: ['error', 'crNhStCritical'], alarm: ['error', 'crNhStAlarm'], high: ['warning', 'crNhStHigh'],
            warning: ['warning', 'crNhStWarning'], normal: ['success', 'crNhStNormal'], nolimit: ['neutral', 'crNhStNoLimit'],
            belowmax: ['neutral', 'crNhStBelowMax'], zero: ['neutral', 'crNhStZero'], implausible: ['neutral', 'crNhStImplausible'],
            none: ['neutral', 'crNhStNone'], bad: ['neutral', 'crNhStBad'], raw: ['neutral', 'crNhStRaw'],
        };

        function CrNhStateBadge({ state, raw }) {
            const { t } = useTranslation();
            const [tone, key] = CR_NH_STATES[state] || CR_NH_STATES.none;
            return (
                <span className="cr-nh-st" data-cr-nh-state={state}>
                    <CrBadge tone={tone} dot={tone !== 'neutral'} title={t(key + 'Hint')}>{crNnT(t, key, { raw: raw || '' })}</CrBadge>
                </span>
            );
        }

        function crNhFmt(n, unit) {
            const s = unit === 'V' ? n.toFixed(2) : unit === 'RPM' || unit === 'W' ? String(Math.round(n)) : n.toFixed(1);
            return unit ? `${s} ${unit}` : s;
        }

        function CrNhValue({ v, unit, t }) {
            if (v.k === 'num') return <span className="cr-mono">{crNhFmt(v.v, unit)}</span>;
            if (v.k === 'text') return <span>{v.raw}</span>;
            if (v.k === 'bad') return <span className="cr-nh-bad" title={t('crNhUnreadableHint')}>{t('crNhUnreadable')}: <span className="cr-mono">{v.raw}</span></span>;
            return <span className="cr-muted cr-nh-none">{t('crNhNotReported')}</span>;
        }

        function CrNodeHardware({ node, read, temps, bmc, loading, onReload, children }) {
            const { t } = useTranslation();
            const m = useMemo(() => crNhModel(read, bmc, node), [read, bmc, node]);
            const hist = useMemo(() => crNhTemps(temps), [temps]);
            const colors = useMemo(() => crSeriesColors(), []);
            const lm = m.lm, inb = m.inband;
            const anyLoading = lm.state === 'loading' || inb.state === 'loading';
            const groupLabel = { temp: t('crNhKindTemp'), fan: t('crNhKindFan'), psu: t('crNhKindPsu'), volt: t('crNhKindVolt'), other: t('crNhKindOther') };
            const toBmc = () => {
                const el = document.querySelector('[data-cr-nh-bmc-anchor]');
                if (el && el.scrollIntoView) el.scrollIntoView({ block: 'start' });
            };
            const judged = m.counts.critical + m.counts.warning + m.counts.normal;
            const overall = { critical: ['error', 'crNhOverallCritical'], warning: ['warning', 'crNhOverallWarning'],
                              normal: ['success', 'crNhOverallNormal'], none: ['neutral', 'crNhOverallNone'] }[m.overall];
            const lmSource = { json: 'crNhSrcJson', text: 'crNhSrcText', hwmon: 'crNhSrcHwmon' };
            const healthKey = { ok: 'crNhStNormal', warning: 'crNhStWarning', critical: 'crNhStCritical' };

            const emptyText = (g) => {
                if (anyLoading) return t('crNhGroupReading');
                if (g === 'psu' && inb.state !== 'ok') return t('crNhPsuNeedsBmc');
                return t('crNhGroupNone');
            };

            return (
                <div className="cr-nn cr-nh" data-cr-nh="">
                    <div className="cr-nn-bar">
                        <h3 className="cr-nn-title">{t('crNhTitle')}</h3>
                        {!anyLoading && (
                            <span data-cr-nh-overall={m.overall}><CrBadge tone={overall[0]} dot={overall[0] !== 'neutral'}>{t(overall[1])}</CrBadge></span>
                        )}
                        {!anyLoading && m.rows.length > 0 && (
                            <span className="cr-muted cr-nn-count" data-cr-nh-judged="">{crNnT(t, 'crNhJudged', { j: judged, n: m.rows.length })}</span>
                        )}
                        <div className="cr-nn-acts">
                            <CrButton icon={<Icons.RotateCw />} onClick={onReload} disabled={loading && lm.state === 'loading'} data-cr-nh-reload="">{t('refresh')}</CrButton>
                        </div>
                    </div>
                    {!anyLoading && m.rows.length > 0 && (
                        <p className="cr-nn-mgmt-line" data-cr-nh-counts="">
                            <span data-cr-nh-count="critical">{crNnT(t, 'crNhCountCritical', { n: m.counts.critical })}</span>
                            <span data-cr-nh-count="warning">{crNnT(t, 'crNhCountWarning', { n: m.counts.warning })}</span>
                            <span data-cr-nh-count="normal">{crNnT(t, 'crNhCountNormal', { n: m.counts.normal })}</span>
                            <span data-cr-nh-count="none">{crNnT(t, 'crNhCountNone', { n: m.counts.none })}</span>
                        </p>
                    )}

                    <ul className="cr-nh-srcs" aria-label={t('crNhSources')}>
                        <li data-cr-nh-src="lm" data-cr-nh-src-state={lm.state}>
                            {lm.state === 'loading' && <span className="cr-nh-srcline"><Icons.RotateCw className="w-3.5 h-3.5 animate-spin" /> {t('crNhLmReading')}</span>}
                            {lm.state === 'ok' && <span className="cr-nh-srcline">{crNnT(t, 'crNhLmOk', { n: lm.rows.length, how: t(lmSource[lm.source]) })}</span>}
                            {lm.state === 'empty' && <span className="cr-nh-srcline">{crNnT(t, 'crNhLmEmpty', { node })}</span>}
                            {lm.state === 'error' && (
                                <div className="cr-callout cr-callout-warning" role="status">
                                    <Icons.AlertTriangle className="w-4 h-4" />
                                    <div>
                                        <p>{crNnT(t, 'crNhLmFailed', { why: crNdWhy(t, lm.fail) })}</p>
                                        {(lm.fail.code === 'SSH_DISABLED' || lm.fail.code === 'NO_SSH_CREDENTIALS' || /ssh/i.test(lm.fail.code || '')) && <p className="cr-muted">{t('crNhLmSshHint')}</p>}
                                    </div>
                                    <button type="button" className="cr-btn cr-btn-xs" onClick={onReload} data-cr-nh-retry="">{t('retry')}</button>
                                </div>
                            )}
                        </li>
                        <li data-cr-nh-src="bmc" data-cr-nh-src-state={inb.state}>
                            {inb.state === 'loading' && <span className="cr-nh-srcline"><Icons.RotateCw className="w-3.5 h-3.5 animate-spin" /> {t('crNhBmcReading')}</span>}
                            {inb.state === 'ok' && (
                                <span className="cr-nh-srcline">
                                    {inb.health
                                        ? crNnT(t, 'crNhBmcOk', { health: t(healthKey[inb.health]), n: inb.rows.length })
                                        : crNnT(t, 'crNhBmcOkNoHealth', { n: inb.rows.length })}
                                    {inb.reasons.length > 0 && inb.health !== 'ok' && <span className="cr-muted"> ({inb.reasons.join(', ')})</span>}
                                </span>
                            )}
                            {inb.state === 'unknown' && <span className="cr-nh-srcline cr-muted">{t('crNhBmcUnknown')}</span>}
                            {inb.state === 'off' && (
                                <span className="cr-nh-srcline">
                                    {t('crNhBmcOff')}{' '}
                                    <button type="button" className="cr-nn-link" onClick={toBmc} data-cr-nh-to-bmc="">{t('crNhBmcGo')}</button>
                                </span>
                            )}
                            {(inb.state === 'error' || inb.state === 'unavailable') && (
                                <span className="cr-nh-srcline">
                                    {crNnT(t, inb.state === 'error' ? 'crNhBmcFailed' : 'crNhBmcUnavailable', { why: inb.why || t('crNdNoAnswer') })}{' '}
                                    <button type="button" className="cr-nn-link" onClick={toBmc} data-cr-nh-to-bmc="">{t('crNhBmcGo')}</button>
                                </span>
                            )}
                        </li>
                    </ul>

                    {(lm.state !== 'loading' || inb.state !== 'loading') && (
                        <div className="cr-nn-scroll">
                            <table className="corp-datagrid cr-table cr-nn-table cr-nh-table" aria-label={t('crNhTitle')}>
                                <thead>
                                    <tr>
                                        <th>{t('crNhSensor')}</th><th>{t('crNhSource')}</th><th className="cr-nh-num">{t('crNhValue')}</th>
                                        <th className="cr-nh-num">{t('crNhMax')}</th><th className="cr-nh-num">{t('crNhCrit')}</th><th>{t('crNhState')}</th>
                                    </tr>
                                </thead>
                                {CR_NH_KINDS.map(g => (
                                    <tbody key={g} data-cr-nh-group={g}>
                                        <tr className="cr-nn-grow"><th colSpan={6} scope="rowgroup">{groupLabel[g]} <span className="cr-muted">{m.groups[g].length}</span></th></tr>
                                        {m.groups[g].length === 0 && (
                                            <tr data-cr-nh-empty={g}>
                                                <td colSpan={6} className="cr-muted">
                                                    {emptyText(g)}
                                                    {g === 'psu' && !anyLoading && inb.state !== 'ok' && (
                                                        <>{' '}<button type="button" className="cr-nn-link" onClick={toBmc}>{t('crNhBmcGo')}</button></>
                                                    )}
                                                </td>
                                            </tr>
                                        )}
                                        {m.groups[g].map((r, i) => (
                                            <tr key={`${r.src}-${r.where}-${r.name}-${i}`} data-cr-nh-row={r.name} data-cr-nh-row-src={r.src}
                                                className={CR_NH_RANK[r.state] === 3 ? 'cr-nh-row-crit' : CR_NH_RANK[r.state] === 2 ? 'cr-nh-row-warn' : ''}>
                                                <td>{r.name || <span className="cr-muted">{t('crNhNoName')}</span>}</td>
                                                <td className="cr-muted cr-nh-where">{r.src === 'bmc' ? t('crNhSrcBmc') : <span className="cr-mono">{r.where}</span>}</td>
                                                <td className="cr-nh-num" data-cr-nh-cell="value"><CrNhValue v={r.value} unit={r.unit} t={t} /></td>
                                                <td className="cr-nh-num" data-cr-nh-cell="max"><CrNhValue v={r.max} unit={r.unit} t={t} /></td>
                                                <td className="cr-nh-num" data-cr-nh-cell="crit"><CrNhValue v={r.crit} unit={r.unit} t={t} /></td>
                                                <td><CrNhStateBadge state={r.state} raw={r.raw} /></td>
                                            </tr>
                                        ))}
                                    </tbody>
                                ))}
                            </table>
                        </div>
                    )}

                    <section className="cr-nn-deps cr-nh-hist" data-cr-nh-hist={hist.state}>
                        <h4 className="cr-nn-sub">{t('crNhHistTitle')}</h4>
                        {hist.state === 'loading' && <div className="cr-nn-state" role="status"><Icons.RotateCw className="w-4 h-4 animate-spin" /> {t('crNhHistReading')}</div>}
                        {hist.state === 'error' && <p className="cr-nh-plain">{crNnT(t, 'crNhHistFailed', { why: crNdWhy(t, hist.fail) })}</p>}
                        {hist.state === 'empty' && <p className="cr-nh-plain cr-muted">{t('crNhHistEmpty')}</p>}
                        {hist.state === 'ok' && (
                            <>
                                <CrChart id="nh-temp" label={t('crNhHistLabel')} timestamps={hist.ts} unit="°C" formatValue={v => v.toFixed(1)}
                                    datasets={[{ label: t('crNhHistLabel'), data: hist.vals, color: colors.net }]} wide />
                                <p className="cr-nn-mgmt-line" data-cr-nh-hist-stats="">
                                    <span>{crNnT(t, 'crNhHistNow', { v: hist.last.toFixed(1) })}</span>
                                    <span>{crNnT(t, 'crNhHistMin', { v: hist.min.toFixed(1) })}</span>
                                    <span>{crNnT(t, 'crNhHistMax', { v: hist.max.toFixed(1) })}</span>
                                    <span data-cr-nh-hist-avg="">{crNnT(t, 'crNhHistAvg', { v: hist.avg.toFixed(1) })}</span>
                                    <span>{crNnT(t, 'crNhHistPoints', { n: hist.vals.length })}</span>
                                    {hist.skipped > 0 && <span data-cr-nh-hist-skipped="">{crNnT(t, 'crNhHistSkipped', { n: hist.skipped })}</span>}
                                </p>
                            </>
                        )}
                        <p className="cr-muted cr-nh-plain">{t('crNhHistNote')}</p>
                    </section>
                    {children}
                    <h4 className="cr-nn-sub cr-nh-bmc-title">{t('crNhBmcTitle')}</h4>
                </div>
            );
        }

        // --- the hardware inventory: processor and memory, disk health, PCI devices ---------------

        // memory and swap of the summary read (get_node_summary sends 0 where the node gave nothing,
        // so a total of 0 is not a size); a swap total of 0 in an answer that has one is no swap space
        function crNhMem(summary) {
            const sum = crNsSummaryState(summary);
            const s = sum === 'ok' ? summary : null;
            const total = (o) => (o && crNhNum(o.total) && o.total > 0 ? o.total : null);
            return { sum, mem: total(s && s.memory), swap: total(s && s.swap), swapNone: !!(s && s.swap && s.swap.total === 0) };
        }

        // the PCI class by the first byte of the code Proxmox VE sends ("0x030000")
        const CR_NH_PCI_CLASS = { '01': 'crNhPciStorage', '02': 'crNhPciNetwork', '03': 'crNhPciDisplay', '04': 'crNhPciMedia',
                                  '05': 'crNhPciMemory', '06': 'crNhPciBridge', '07': 'crNhPciComm', '08': 'crNhPciSystem',
                                  '09': 'crNhPciInput', '0c': 'crNhPciSerial', '0d': 'crNhPciWireless', '10': 'crNhPciCrypto',
                                  '12': 'crNhPciAccel' };
        function crNhPciClass(code) {
            const m = /^(?:0x)?([0-9a-f]{2})[0-9a-f]{0,4}$/i.exec(String(code == null ? '' : code).trim());
            if (!m) return { base: '', key: '' };
            const base = m[1].toLowerCase();
            return { base, key: CR_NH_PCI_CLASS[base] || '' };
        }

        // GET .../hardware/pci as loadTabData kept it: loading, failed with why, empty or the devices.
        // An IOMMU group below 0 (or none) is a device outside every group; mdev marks a device that
        // offers mediated devices. The route answers [] for a node that refused, so empty is said
        // with that doubt
        function crNhPci(read) {
            if (read === undefined) return { state: 'loading', rows: [] };
            const f = crNdFail(read);
            if (f) return { state: 'error', fail: f, rows: [] };
            if (!Array.isArray(read)) {
                return { state: 'error', fail: { status: 200, error: (read && typeof read.error === 'string') ? read.error : '', code: 'NOT_JSON' }, rows: [] };
            }
            const str = (v) => (typeof v === 'string' ? v.trim() : '');
            const rows = read.filter(d => d && typeof d === 'object').map(d => {
                const g = crNhNum(d.iommugroup) ? d.iommugroup
                    : (typeof d.iommugroup === 'string' && /^\s*-?\d+\s*$/.test(d.iommugroup) ? parseInt(d.iommugroup, 10) : null);
                const cls = crNhPciClass(d.class);
                return {
                    id: str(d.id), classCode: str(d.class), classBase: cls.base, classKey: cls.key,
                    vendor: str(d.vendor_name), vendorId: str(d.vendor), device: str(d.device_name), deviceId: str(d.device),
                    subVendor: str(d.subsystem_vendor_name), subDevice: str(d.subsystem_device_name),
                    group: g != null && g >= 0 ? g : null, mdev: d.mdev === true || d.mdev === 1 || d.mdev === '1',
                };
            });
            rows.sort((a, b) => a.id.localeCompare(b.id));
            return { state: rows.length ? 'ok' : 'empty', rows, grouped: rows.filter(r => r.group != null).length };
        }

        function crNhPciMatch(r, { cls, q }) {
            if (cls !== 'all' && r.classBase !== cls) return false;
            const s = String(q || '').trim().toLowerCase();
            if (!s) return true;
            return [r.id, r.vendor, r.device, r.subVendor, r.subDevice, r.vendorId, r.deviceId, r.classCode]
                .some(v => v && v.toLowerCase().includes(s));
        }

        window.PegaProxNodeInv = Object.freeze({ mem: crNhMem, pciClass: crNhPciClass, pci: crNhPci, pciMatch: crNhPciMatch });

        // processor and memory from the summary read the view holds, and the health and wear that
        // disks/list gives each disk (SMART detail, temperature and error counters stay on Configure > Disks)
        function CrNodeHwBasics({ summary, disks, loading, onReadDisks, onOpenDisks }) {
            const { t } = useTranslation();
            const mem = crNhMem(summary);
            const miss = mem.sum === 'loading' ? t('crNcReadingShort') : mem.sum === 'error' ? t('crNcSumFailedShort') : undefined;
            const ci = mem.sum === 'ok' && summary.cpuinfo && typeof summary.cpuinfo === 'object' ? summary.cpuinfo : {};
            const cpu = crNcCpu(t, ci, miss);
            const dm = useMemo(() => crNdModel(disks, {}), [disks]);
            const failed = dm.rows.filter(r => r.health.state === 'failed').length;
            const unknown = dm.rows.filter(r => r.health.state === 'none').length;
            const wear = (r) => {
                if (r.wear.state === 'ok') return <span className="cr-mono" title={crNnT(t, 'crNdWearLeft', { n: r.wear.left })}>{crNnT(t, 'crNdWearUsed', { n: r.wear.used })}</span>;
                if (r.wear.state === 'bad') return <span className="cr-nh-bad">{t('crNhUnreadable')}: <span className="cr-mono">{r.wear.raw}</span></span>;
                return <CrNcMissing />;
            };
            let diskBody;
            if (dm.state === 'loading') {
                diskBody = disks === undefined && !loading
                    ? <CrNcState id="hw-disks" kind="empty" onRetry={onReadDisks}>{t('crNcNotRead')}</CrNcState>
                    : <CrNcState id="hw-disks" kind="loading" />;
            } else if (dm.state === 'error') {
                diskBody = <CrNcState id="hw-disks" kind="error" onRetry={onReadDisks} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, dm.fail) })}</CrNcState>;
            } else if (dm.state === 'empty') {
                diskBody = <CrNcState id="hw-disks" kind="empty" onRetry={onReadDisks} retryDisabled={loading}>{t('crNhDiskEmpty')}</CrNcState>;
            } else {
                diskBody = (
                    <div className="cr-nn-scroll">
                        <table className="corp-datagrid cr-table cr-nn-table" aria-label={t('crNhDiskTitle')}>
                            <thead><tr><th>{t('crNdDisk')}</th><th>{t('crNdTypeSize')}</th><th>{t('crNdHealth')}</th><th>{t('crNdWear')}</th></tr></thead>
                            <tbody>
                                {dm.rows.map(r => (
                                    <tr key={r.dev || r.disk.devpath} data-cr-nh-disk={r.dev} className={r.health.state === 'failed' ? 'cr-nh-row-crit' : ''}>
                                        <td>
                                            <span className="cr-mono">{r.disk.devpath || <CrNcMissing />}</span>
                                            {String(r.disk.model || '').trim() && <span className="cr-nd-ident cr-muted">{String(r.disk.model).trim()}</span>}
                                        </td>
                                        <td>
                                            <span>{CR_ND_TYPES[r.type] || <span className="cr-muted">{t('crNdTypeUnknown')}</span>}</span>
                                            <span className="cr-muted"> {crNhNum(r.size) && r.size > 0 ? formatBytes(r.size) : t('crNdSizeUnknown')}</span>
                                        </td>
                                        <td data-cr-nh-disk-cell="health"><CrNdHealth h={r.health} t={t} /></td>
                                        <td data-cr-nh-disk-cell="wear">{wear(r)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                );
            }
            return (
                <div className="cr-nc-cols cr-nh-basics" data-cr-nh-basics="">
                    <CrNcSection id="hw-cpu" data-cr-nh-cpu={mem.sum} title={t('crNhCpuMemTitle')} desc={t('crNhCpuMemDesc')}>
                        <div className="cr-nc-groups">
                            <CrNcGroup id="hw-cpu" title={t('crNcGrpCpu')}>
                                <CrNcKv id="hw-cpu" rows={cpu.rows} />
                                <CrNcCpuFlags flags={cpu.flags} />
                            </CrNcGroup>
                            <CrNcGroup id="hw-mem" title={t('memory')}>
                                <CrNcKv id="hw-mem" rows={[
                                    { k: 'mem', label: t('crNhMemTotal'), value: mem.mem != null ? formatBytes(mem.mem) : '', missing: miss },
                                    { k: 'swap', label: t('crNhSwapTotal'), value: mem.swap != null ? formatBytes(mem.swap) : mem.swapNone ? t('crNhSwapNone') : '', missing: miss },
                                    { k: 'dimm', label: t('crNhDimms'), value: '', missing: t('crNhDimmsNone') },
                                ]} />
                            </CrNcGroup>
                        </div>
                    </CrNcSection>
                    <CrNcSection id="hw-disks" data-cr-nh-disks={dm.state} title={t('crNhDiskTitle')} desc={t('crNhDiskDesc')}
                        badge={dm.state === 'ok' ? (
                            <>
                                <span className="cr-muted cr-nn-count">{crNnT(t, 'crNdCount', { n: dm.rows.length })}</span>
                                {failed > 0 && <span data-cr-nh-disks-failed=""><CrBadge tone="error">{crNnT(t, 'crNdFailedBadge', { n: failed })}</CrBadge></span>}
                                {unknown > 0 && <CrBadge tone="neutral" dot={false}>{crNnT(t, 'crNdUnknownBadge', { n: unknown })}</CrBadge>}
                            </>
                        ) : null}
                        actions={<CrButton className="cr-btn-xs" onClick={onOpenDisks} data-cr-nh-open-disks="">{t('crNhOpenDisks')}</CrButton>}>
                        {diskBody}
                    </CrNcSection>
                </div>
            );
        }

        // the PCI devices Proxmox VE lists for passthrough (it leaves out memory controllers,
        // bridges and processors by default): one read per visit of the tab, filtered here
        function CrNodePci({ read, loading, onReload }) {
            const { t } = useTranslation();
            const m = useMemo(() => crNhPci(read), [read]);
            const [cls, setCls] = useState('all');
            const [q, setQ] = useState('');
            const classes = useMemo(() => {
                const c = new Map();
                for (const r of m.rows) c.set(r.classBase, (c.get(r.classBase) || 0) + 1);
                return [...c.entries()].sort((a, b) => a[0].localeCompare(b[0]));
            }, [m.rows]);
            const className = (r) => (r.classKey ? t(r.classKey) : r.classBase ? crNnT(t, 'crNhPciClassN', { c: r.classBase }) : t('crNhNotReported'));
            const filter = useCallback((r) => crNhPciMatch(r, { cls, q }), [cls, q]);
            const columns = useMemo(() => [
                { key: 'id', label: t('crNhPciAddr'), width: 108, mono: true, sortValue: r => r.id || null,
                  render: r => <span data-cr-nh-pci-row={r.id}>{r.id || <CrNcMissing />}</span> },
                { key: 'class', label: t('crNhPciClass'), width: 168, sortValue: r => r.classBase || null,
                  render: r => (
                      <span className="cr-nh-pci-class" title={r.classCode || undefined}>
                          {className(r)}{r.classCode && <span className="cr-muted cr-mono"> {r.classCode}</span>}
                      </span>
                  ) },
                // vendor and device, the subsystem, then the IDs as lspci prints them ([vendor:device])
                { key: 'device', label: t('crNhPciDevice'), flex: true, min: 180, sortValue: r => `${r.vendor} ${r.device}`.trim() || null,
                  render: r => {
                      const ids = r.vendorId || r.deviceId ? `${r.vendorId.replace(/^0x/i, '')}:${r.deviceId.replace(/^0x/i, '')}` : '';
                      const sub = [r.subVendor, r.subDevice].filter(Boolean).join(' ');
                      const name = [r.vendor, r.device].filter(Boolean).join(' ');
                      return (
                          <span className="cr-nh-pci-dev" title={[name, sub, ids && `[${ids}]`].filter(Boolean).join(' · ') || undefined}>
                              <span>{name || <CrNcMissing />}</span>
                              {sub && <span className="cr-muted"> · {sub}</span>}
                              {ids && <span className="cr-muted cr-mono" data-cr-nh-pci-ids={ids}> [{ids}]</span>}
                          </span>
                      );
                  } },
                { key: 'group', label: t('crNhPciGroup'), width: 96, sortValue: r => r.group,
                  render: r => (r.group != null ? <span className="cr-mono" data-cr-nh-pci-group={r.group}>{r.group}</span>
                      : <span className="cr-muted" data-cr-nh-pci-group="none" title={t('crNhPciNoGroupHint')}>{t('crNhPciNoGroup')}</span>) },
                { key: 'mdev', label: t('crNhPciMdev'), width: 112, title: t('crNhPciMdevHint'), sortValue: r => (r.mdev ? 1 : 0),
                  render: r => (r.mdev ? <span data-cr-nh-pci-mdev="yes"><CrBadge tone="neutral" dot={false}>{t('crNhPciMdevYes')}</CrBadge></span>
                      : <span className="cr-muted" data-cr-nh-pci-mdev="no">{t('crNhPciMdevNo')}</span>) },
            ], [t]);
            const active = (cls !== 'all' ? 1 : 0) + (q.trim() ? 1 : 0);
            let body;
            if (m.state === 'loading') {
                body = loading ? <CrNcState id="pci" kind="loading" /> : <CrNcState id="pci" kind="empty" onRetry={onReload}>{t('crNcNotRead')}</CrNcState>;
            } else if (m.state === 'error') {
                body = <CrNcState id="pci" kind="error" onRetry={onReload} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, m.fail) })}</CrNcState>;
            } else if (m.state === 'empty') {
                body = <CrNcState id="pci" kind="warning" onRetry={onReload} retryDisabled={loading}>{t('crNhPciEmpty')}</CrNcState>;
            } else {
                body = (
                    <>
                        {m.grouped === 0 && <CrNcState id="pci-iommu" kind="warning">{t('crNhPciNoIommu')}</CrNcState>}
                        <CrTable id="node-pci" columns={columns} rows={m.rows} filter={filter} rowKey={r => r.id || `${r.vendorId}:${r.deviceId}`}
                            ariaLabel={t('crNhPciTitle')} initialSort={{ key: 'id', dir: 'asc' }} emptyText={t('crNhPciNoMatch')} maxHeight={440}
                            toolbar={(
                                <div className="cr-tc-filters cr-nt-filters">
                                    <select className="cr-select" value={cls} onChange={e => setCls(e.target.value)} data-cr-nh-pci-class=""
                                        aria-label={t('crNhPciClass')}>
                                        <option value="all">{crNnT(t, 'crNhPciAllClasses', { n: m.rows.length })}</option>
                                        {classes.map(([c, n]) => {
                                            const key = CR_NH_PCI_CLASS[c];
                                            return <option key={c} value={c}>{`${key ? t(key) : crNnT(t, 'crNhPciClassN', { c: c || '?' })} (${n})`}</option>;
                                        })}
                                    </select>
                                    <div className="cr-search-box">
                                        <Icons.Search className="cr-search-ico" />
                                        <input type="search" className="cr-input" value={q} data-cr-nh-pci-q="" placeholder={t('crNhPciSearch')}
                                            aria-label={t('crNhPciSearch')} onChange={e => setQ(e.target.value)} />
                                    </div>
                                    {active > 0 && (
                                        <button type="button" className="cr-btn cr-btn-ghost" data-cr-nh-pci-clear=""
                                            onClick={() => { setCls('all'); setQ(''); }}>{t('crNgClear')}</button>
                                    )}
                                </div>
                            )} />
                    </>
                );
            }
            return (
                <CrNcSection id="pci" data-cr-nh-pci={m.state} title={t('crNhPciTitle')} desc={t('crNhPciDesc')}
                    badge={m.state === 'ok' ? <span className="cr-muted cr-nn-count">{crNnT(t, m.rows.length === 1 ? 'crNhPciOne' : 'crNhPciN', { n: m.rows.length })}</span> : null}
                    actions={<CrButton icon={<Icons.RotateCw />} onClick={onReload} disabled={loading && m.state === 'loading'} data-cr-nh-pci-reload="">{t('refresh')}</CrButton>}>
                    {body}
                </CrNcSection>
            );
        }

        // --- the disks sub tab -------------------------------------------------------------------

        const CR_ND_TYPES = { hdd: 'HDD', ssd: 'SSD', nvme: 'NVMe', usb: 'USB' };

        function CrNdHealth({ h, t }) {
            const tone = h.state === 'ok' ? 'success' : h.state === 'failed' ? 'error' : 'neutral';
            const text = h.state === 'none' ? t('crNhNotReported') : h.state === 'off' ? t('crNdSmartOff') : h.text;
            return <span data-cr-nd-health={h.state}><CrBadge tone={tone} dot={tone !== 'neutral'} title={t('crNdHealthHint')}>{text}</CrBadge></span>;
        }

        function CrNodeDisks({ node, clusterId, read, loading, authFetch, onReload }) {
            const { t } = useTranslation();
            const [smart, setSmart] = useState({});   // dev -> {state: reading|ok|error, data, fail}
            const [zfs, setZfs] = useState({});       // pool -> {state: reading|ok|error, detail, fail}
            const [busy, setBusy] = useState(false);
            const [modal, setModal] = useState(null);
            const alive = useRef(true);
            useEffect(() => () => { alive.current = false; }, []);
            const m = useMemo(() => crNdModel(read, zfs), [read, zfs]);
            const base = `${API_URL}/clusters/${encodeURIComponent(clusterId)}/nodes/${encodeURIComponent(node)}`;
            // LW Nov 2026 - round 10: the disk writes of the classic node dialog (cr_nodestore.js)
            const gate = useCrDoGate();
            const ops = useCrDoOps({ clusterId, node, authFetch, onReload });
            const lists = crDoLists(read, t);
            const unused = m.state === 'ok' ? m.rows.filter(r => crDoIsUnused(r.disk)) : [];

            const readSmart = async (d) => {
                const dev = crNdDev(d.devpath);
                setSmart(p => ({ ...p, [dev]: { state: 'reading' } }));
                const body = await crNdRead(await authFetch(`${base}/disks/${encodeURIComponent(dev)}/smart`));
                if (!alive.current) return null;
                const f = crNdFail(body);
                const v = f ? { state: 'error', fail: f } : { state: 'ok', data: body };
                setSmart(p => ({ ...p, [dev]: v }));
                return v;
            };
            const readPool = async (pool) => {
                setZfs(p => ({ ...p, [pool]: { state: 'reading' } }));
                const body = await crNdRead(await authFetch(`${base}/disks/zfs/${encodeURIComponent(pool)}`));
                if (!alive.current) return;
                const f = crNdFail(body);
                setZfs(p => ({ ...p, [pool]: f ? { state: 'error', fail: f } : { state: 'ok', detail: body } }));
            };
            // one request per disk and per pool, three at a time, only on this click
            const readAll = async () => {
                if (busy || m.state !== 'ok') return;
                setBusy(true);
                const jobs = [...m.rows.map(r => () => readSmart(r.disk)), ...m.zpools.map(p => () => readPool(p))];
                let next = 0;
                const worker = async () => {
                    while (next < jobs.length && alive.current) {
                        const job = jobs[next++];
                        try { await job(); } catch (e) { console.warn('[cr] disk detail read:', e && e.message); }
                    }
                };
                await Promise.all([worker(), worker(), worker()]);
                if (alive.current) setBusy(false);
            };
            const openSmart = async (row) => {
                const have = smart[row.dev];
                if (have && have.state === 'ok') { setModal({ disk: row.disk, loading: false, data: have.data, error: null }); return; }
                setModal({ disk: row.disk, loading: true, data: null, error: null });
                const v = await readSmart(row.disk);
                if (!v) return;
                setModal(cur => (cur && cur.disk === row.disk
                    ? { disk: row.disk, loading: false, data: v.state === 'ok' ? v.data : null, error: v.state === 'ok' ? null : crNdWhy(t, v.fail) }
                    : cur));
            };

            const read_ = Object.keys(smart).filter(k => smart[k].state === 'ok').length;
            const failed = m.rows.filter(r => r.health.state === 'failed').length;
            const unknown = m.rows.filter(r => r.health.state === 'none').length;
            const notRead = <span className="cr-muted cr-nd-unread">{t('crNdNotRead')}</span>;
            const sideFail = m.state === 'ok' ? [['lvm', 'crNdLvm'], ['thin', 'crNdThin'], ['zfs', 'crNdZfs']].filter(([k]) => m.side[k]) : [];

            const tempCell = (r) => {
                const s = smart[r.dev];
                if (!s) return notRead;
                if (s.state === 'reading') return <span className="cr-muted"><Icons.RotateCw className="w-3 h-3 animate-spin inline" /> {t('crNdReadingOne')}</span>;
                if (s.state === 'error') return <span className="cr-nh-bad" title={crNdWhy(t, s.fail)}>{t('crNdSmartFailed')}</span>;
                const p = crNdSmart(s.data);
                if (p.temp.k === 'num') return <span className="cr-mono">{p.temp.v} °C</span>;
                if (p.temp.k === 'bad') return <span className="cr-nh-bad" title={t('crNhUnreadableHint')}>{t('crNhUnreadable')}: <span className="cr-mono">{p.temp.raw}</span></span>;
                return <span className="cr-muted cr-nh-none">{t('crNhNotReported')}</span>;
            };
            const wearCell = (r) => {
                if (r.wear.state === 'ok') return <span className="cr-mono" title={crNnT(t, 'crNdWearLeft', { n: r.wear.left })}>{crNnT(t, 'crNdWearUsed', { n: r.wear.used })}</span>;
                if (r.wear.state === 'bad') return <span className="cr-nh-bad">{t('crNhUnreadable')}: <span className="cr-mono">{r.wear.raw}</span></span>;
                const s = smart[r.dev];
                const p = s && s.state === 'ok' ? crNdSmart(s.data) : null;
                if (p && p.wearUsed != null) return <span className="cr-mono" title={t('crNdWearFromSmart')}>{crNnT(t, 'crNdWearUsed', { n: p.wearUsed })}</span>;
                return <span className="cr-muted cr-nh-none">{t('crNhNotReported')}</span>;
            };
            const errCell = (r) => {
                const items = [];
                const s = smart[r.dev];
                const p = s && s.state === 'ok' ? crNdSmart(s.data) : null;
                if (p) for (const e of p.errors) items.push({ label: t(e.key), n: e.n, bad: e.bad, hard: e.hard });
                for (const u of r.uses) {
                    if (u.kind !== 'zfs') continue;
                    for (const [k, key] of [['read', 'crNdErrZfsRead'], ['write', 'crNdErrZfsWrite'], ['cksum', 'crNdErrZfsCksum']]) {
                        if (crNhNum(u[k])) items.push({ label: crNnT(t, key, { pool: u.name }), n: u[k], hard: true });
                    }
                }
                const out = [];
                if (p && p.critWarn) out.push(<span key="cw" className="cr-nd-err cr-nd-err-hard" data-cr-nd-err="critwarn">{crNnT(t, 'crNdCritWarn', { v: typeof p.critWarn === 'number' ? '0x' + p.critWarn.toString(16) : p.critWarn })}</span>);
                if (p && p.failing.length) out.push(<span key="fl" className="cr-nd-err cr-nd-err-hard" data-cr-nd-err="failing">{crNnT(t, 'crNdFailing', { list: p.failing.join(', ') })}</span>);
                const nonzero = items.filter(x => x.bad != null || x.n > 0);
                for (const x of nonzero) {
                    out.push(<span key={x.label} className={`cr-nd-err${x.hard && x.bad == null ? ' cr-nd-err-hard' : ''}`} data-cr-nd-err={x.label}>
                        {x.label}: {x.bad != null ? <>{t('crNhUnreadable')} <span className="cr-mono">{x.bad}</span></> : <span className="cr-mono">{x.n}</span>}
                    </span>);
                }
                const zeros = items.length - nonzero.length;
                if (zeros > 0) out.push(<span key="z" className="cr-muted" data-cr-nd-err="zero">{crNnT(t, nonzero.length ? 'crNdErrOthersZero' : 'crNdErrAllZero', { n: zeros })}</span>);
                if (out.length) return <span className="cr-nd-errs">{out}</span>;
                if (!s) return notRead;
                if (s.state === 'reading') return <span className="cr-muted">{t('crNdReadingOne')}</span>;
                if (s.state === 'error') return <span className="cr-nh-bad" title={crNdWhy(t, s.fail)}>{t('crNdSmartFailed')}</span>;
                return <span className="cr-muted cr-nh-none">{t('crNhNotReported')}</span>;
            };
            const useCell = (r) => {
                const out = r.uses.map((u, i) => (
                    <span key={i} className="cr-nd-use" data-cr-nd-use={u.kind}>
                        {u.kind === 'lvm' && crNnT(t, u.thin.length ? 'crNdUseLvmThin' : 'crNdUseLvm', { vg: u.name, thin: u.thin.join(', ') })}
                        {u.kind === 'ceph' && crNnT(t, 'crNdUseCeph', { id: u.name })}
                        {u.kind === 'zfs' && crNnT(t, u.vstate && u.vstate.toUpperCase() !== 'ONLINE' ? 'crNdUseZfsState' : 'crNdUseZfs', { pool: u.name, state: u.vstate })}
                    </span>
                ));
                if (r.zfsState) out.push(<span key="zs" className="cr-nd-use cr-muted" data-cr-nd-use="zfs-open">{t({ unread: 'crNdZfsUnread', failed: 'crNdZfsFailed', nomatch: 'crNdZfsNoMatch', nopool: 'crNdZfsNoPool' }[r.zfsState])}</span>);
                // round 10: 'unused' is how the classic dialog knows a free disk, not a use
                if (r.usedText && !crDoIsUnused(r.disk) && !r.uses.length && !r.zfsState) out.push(<span key="ut" className="cr-nd-use" data-cr-nd-use="pve">{crNnT(t, 'crNdUsePve', { used: r.usedText })}</span>);
                if (!out.length) return <span className="cr-muted cr-nh-none">{t('crNdUseNone')}</span>;
                return <span className="cr-nd-uses">{out}</span>;
            };

            // LW Nov 2026 - round 7: the section card of cr_nodecfg.js, the same hooks and states as before
            return (
                <CrNcSection id="disks" className="cr-nd" data-cr-nd="" title={t('disks')} desc={t('crNvDisksDesc')}
                    badge={m.state === 'ok' ? (
                        <>
                            <span className="cr-muted cr-nn-count">{crNnT(t, 'crNdCount', { n: m.rows.length })}</span>
                            {failed > 0 && <span data-cr-nd-failed=""><CrBadge tone="error">{crNnT(t, 'crNdFailedBadge', { n: failed })}</CrBadge></span>}
                            {unknown > 0 && <span data-cr-nd-unknown=""><CrBadge tone="neutral" dot={false}>{crNnT(t, 'crNdUnknownBadge', { n: unknown })}</CrBadge></span>}
                        </>
                    ) : null}
                    actions={(
                        <>
                            <CrButton icon={<Icons.Activity />} onClick={readAll} disabled={busy || m.state !== 'ok'} data-cr-nd-readall="">
                                {busy ? t('crNdReading') : t('crNdReadAll')}
                            </CrButton>
                            <CrButton icon={<Icons.RotateCw />} onClick={onReload} disabled={loading && m.state === 'loading'} data-cr-nd-reload="">{t('refresh')}</CrButton>
                        </>
                    )}>
                    {m.state === 'ok' && (
                        <p className="cr-nn-mgmt-line" data-cr-nd-note="">
                            <span>{crNnT(t, 'crNdReadNote', { n: read_, total: m.rows.length })}</span>
                            <span data-cr-nd-io="">{t('crNdIoNote')}</span>
                        </p>
                    )}
                    <CrDoDone done={ops.done} onDismiss={ops.dismiss} />
                    {sideFail.map(([k, key]) => (
                        <CrNcState key={k} id={`disks-${k}`} kind="warning" data-cr-nd-side={k}>
                            {crNnT(t, 'crNdSideFailed', { what: t(key), why: crNdWhy(t, m.side[k]) })}
                        </CrNcState>
                    ))}
                    {m.state === 'loading' && <CrNcState id="disks" kind="loading" data-cr-nd-list="loading">{t('crNdReadingList')}</CrNcState>}
                    {m.state === 'error' && (
                        <CrNcState id="disks" kind="error" onRetry={onReload} data-cr-nd-list="error">{crNnT(t, 'crNdListFailed', { node, why: crNdWhy(t, m.fail) })}</CrNcState>
                    )}
                    {m.state === 'empty' && (
                        <CrNcState id="disks" kind="warning" onRetry={onReload} data-cr-nd-list="empty">{crNnT(t, 'crNdListEmpty', { node })}</CrNcState>
                    )}
                    {m.state === 'ok' && (
                        <div className="cr-nn-scroll">
                            <table className="corp-datagrid cr-table cr-nn-table cr-nd-table" aria-label={t('disks')}>
                                <thead>
                                    <tr>
                                        <th>{t('crNdDisk')}</th><th>{t('crNdTypeSize')}</th><th>{t('crNdHealth')}</th><th>{t('crNdTemp')}</th>
                                        <th>{t('crNdWear')}</th><th>{t('crNdErrors')}</th><th>{t('crNdUsedBy')}</th><th aria-label={t('actions')}></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {m.rows.map(r => {
                                        const d = r.disk;
                                        const ident = [d.model, d.serial].map(x => String(x || '').trim()).filter(Boolean);
                                        return (
                                            <tr key={r.dev || d.devpath} data-cr-nd-row={r.dev} className={r.health.state === 'failed' ? 'cr-nh-row-crit' : ''}>
                                                <td>
                                                    <span className="cr-mono cr-nn-name">{d.devpath || '-'}</span>
                                                    <span className="cr-nd-ident cr-muted">{ident.length ? ident.join(' · ') : t('crNdNoIdent')}</span>
                                                </td>
                                                <td data-cr-nd-cell="type">
                                                    <span>{CR_ND_TYPES[r.type] || <span className="cr-muted">{t('crNdTypeUnknown')}</span>}</span>
                                                    {r.type === 'hdd' && crNhNum(d.rpm) && d.rpm > 0 && <span className="cr-muted"> {d.rpm} rpm</span>}
                                                    <span className="cr-nd-ident">{crNhNum(r.size) && r.size > 0 ? formatBytes(r.size) : <span className="cr-muted">{t('crNdSizeUnknown')}</span>}</span>
                                                </td>
                                                <td data-cr-nd-cell="health"><CrNdHealth h={r.health} t={t} /></td>
                                                <td data-cr-nd-cell="temp">{tempCell(r)}</td>
                                                <td data-cr-nd-cell="wear">{wearCell(r)}</td>
                                                <td data-cr-nd-cell="errors">{errCell(r)}</td>
                                                <td data-cr-nd-cell="use">{useCell(r)}</td>
                                                <td className="cr-nn-rowacts">
                                                    <span className="cr-do-rowacts">
                                                        <CrButton className="cr-btn-xs" onClick={() => openSmart(r)} data-cr-nd-smart={r.dev}>{t('crNdSmart')}</CrButton>
                                                        {/* as in the classic dialog: Initialize GPT and Wipe only for a disk PVE lists as unused */}
                                                        {crDoIsUnused(d) ? (
                                                            <span className="cr-do-danger-acts" data-cr-do-acts={r.dev}>
                                                                {/* icons as in the classic table, so the column stays as wide as SMART; the name is the label */}
                                                                <CrButton variant="danger" className="cr-btn-xs cr-do-ico" icon={<Icons.Plus />} disabled={!gate.ok || ops.busy}
                                                                    title={gate.ok ? crNnT(t, 'crDoGptOn', { disk: d.devpath }) : gate.why} aria-label={crNnT(t, 'crDoGptOn', { disk: d.devpath })}
                                                                    onClick={() => ops.open({ kind: 'initgpt', disk: d })} data-cr-do-gpt={r.dev} />
                                                                <CrButton variant="danger" className="cr-btn-xs cr-do-ico" icon={<Icons.Trash />} disabled={!gate.ok || ops.busy}
                                                                    title={gate.ok ? crNnT(t, 'crDoWipeOn', { disk: d.devpath }) : gate.why} aria-label={crNnT(t, 'crDoWipeOn', { disk: d.devpath })}
                                                                    onClick={() => ops.open({ kind: 'wipe', disk: d })} data-cr-do-wipe={r.dev} />
                                                            </span>
                                                        ) : (
                                                            <span className="cr-muted cr-do-inuse" data-cr-do-inuse={r.dev}
                                                                title={crNnT(t, 'crDoInUseHint', { used: r.usedText || t('crDoInUseSome') })}>{t('crDoInUse')}</span>
                                                        )}
                                                    </span>
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                    {m.state === 'ok' && (
                        <CrNcGroup id="do-create" title={t('crDoCreateTitle')}>
                            <div className="cr-do-create" data-cr-do-create="">
                                <p className="cr-muted" data-cr-do-unused={unused.length}>
                                    {unused.length ? crNnT(t, unused.length === 1 ? 'crDoUnusedOne' : 'crDoUnusedN', { n: unused.length, list: unused.map(r => r.dev).join(', ') })
                                        : crNnT(t, 'crDoNoUnused', { node })}
                                </p>
                                <div className="cr-do-create-acts">
                                    {['lvm', 'lvmthin', 'directory', 'zfs'].map(ty => <CrDoNew key={ty} type={ty} ops={ops} gate={gate} short />)}
                                </div>
                            </div>
                        </CrNcGroup>
                    )}
                    <CrDoGate gate={gate} />
                    {modal && <SmartModal modal={modal} onClose={() => setModal(null)} formatBytes={formatBytes} />}
                    <CrDoDialogs ops={ops} node={node} {...lists} />
                </CrNcSection>
            );
        }

        // ═══════════════════════════════════════════════════════════
        // Summary, tasks and guests of a node - LW Nov 2026
        // Summary: the health of the node from what the view already holds (the cluster metrics, the
        // node summary, the sensors the Hardware tab read, the active alerts the alert strip read),
        // each condition with the limit it was judged by. CPU and memory open Monitor > Performance.
        // Tasks: the node's task list (GET .../tasks, the newest 50) by state as Proxmox VE keeps it:
        // no end time is running, "OK" ok, "WARNINGS: n" a warning, anything else failed. A row opens
        // its log in the task center's log pane (GET .../tasks/<upid>/log, and /status while it runs).
        // Guests: the cluster resources of the node, searched, filtered and sorted in the page; the
        // guest agent only where the IP sweep set agent_running. No request per guest.
        // ═══════════════════════════════════════════════════════════

        const crNsNum = (v) => {
            const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
            return typeof n === 'number' && Number.isFinite(n) ? n : null;
        };
        const CR_NS_RANK = { critical: 3, warning: 2, info: 1 };
        // get_node_summary answers {} when it cannot read the node, a failed request is null here
        function crNsSummaryState(s) {
            if (s === undefined) return 'loading';
            if (s === null || typeof s !== 'object') return 'error';
            return s.pveversion || crNsNum(s.uptime) ? 'ok' : 'empty';
        }

        // the hardware the page has read: the lm-sensors answer of the Hardware tab and the rows the
        // in-band panel handed up, each with when it came. Nothing read yet is said as such, never
        // as normal; a source that was not read is named, and the age of the oldest read is kept
        function crNsHardware(hw, node) {
            if (!hw) return { state: 'na' };
            const lmKnown = hw.read !== undefined;
            const bmcKnown = !!(hw.bmc && hw.bmc.node === node && !hw.bmc.loading);
            if (!lmKnown && !bmcKnown) return { state: 'unread' };
            const mod = crNhModel(lmKnown ? hw.read : undefined, bmcKnown ? hw.bmc : null, node);
            const bad = mod.rows.filter(r => (CR_NH_RANK[r.state] || 0) >= 2).map(r => r.name || '-');
            const names = bad.length ? bad : (mod.inband.reasons || []);
            const judged = mod.counts.critical + mod.counts.warning + mod.counts.normal;
            const times = [lmKnown ? crNsNum(hw.readAt) : null, bmcKnown ? crNsNum(hw.bmc.at) : null].filter(x => x != null);
            return { state: mod.overall, bad: bad.length, names, judged, total: mod.rows.length, lm: mod.lm.state, inband: mod.inband.state,
                     lmUnread: !lmKnown, inbandUnread: !bmcKnown, at: times.length ? Math.min(...times) : null };
        }

        // the firing alerts of this node out of what the alert strip read for its cluster. A read
        // older than three of the strip's rounds is not taken for now
        function crNsAlerts(seen, node, now) {
            if (!seen) return { state: 'unread' };
            if (seen.state !== 'ok' || !Array.isArray(seen.rows)) return { state: 'error' };
            const at = crNsNum(seen.at);
            if (at != null && now - at > 3 * CR_AL.incidentsEvery) return { state: 'old', at };
            const mine = seen.rows.filter(r => r && r.target_type === 'node' && r.target_name === node);
            const sev = { critical: 0, warning: 0, info: 0 };
            let acked = 0;
            for (const r of mine) {
                sev[r.severity === 'critical' ? 'critical' : r.severity === 'warning' ? 'warning' : 'info']++;
                if (r.acked_at) acked++;
            }
            return { state: 'ok', n: mine.length, sev, acked };
        }

        function crNsModel({ metrics, summary, hw, alerts, node, now }) {
            if (!crNsNum(now)) now = Date.now();
            const m = metrics && typeof metrics === 'object' && Object.keys(metrics).length ? metrics : null;
            const sum = crNsSummaryState(summary);
            const s = sum === 'ok' ? summary : null;
            const items = [];
            const missing = [];
            const add = (id, level, key, vars) => items.push({ id, level, key, vars: vars || {} });
            const status = m ? String(m.status || '') : '';
            const offline = !!m && (status === 'offline' || m.offline === true);
            const state = !m ? 'none' : offline ? 'offline' : status === 'online' ? 'online' : 'unknown';
            if (state === 'offline') add('status', 'critical', 'crNsOffline');
            else if (state === 'unknown') add('status', 'warning', 'crNsStatusUnknown', { status: status || '-' });
            else if (state === 'none') missing.push('status');
            if (m && m.maintenance_mode) add('maint', 'warning', 'crNsMaint');
            if (m && m.is_updating) add('update', 'info', 'crNsUpdating');

            // the live figures: the zeros of a node that is not online are no measurement
            const live = state === 'online';
            const cpu = live ? crNsNum(m.cpu_percent) : null;
            const memUsed = live ? crNsNum(m.mem_used) : null;
            const memTotal = live ? crNsNum(m.mem_total) : null;
            const mem = memTotal > 0 && memUsed != null ? memUsed * 100 / memTotal : null;
            let rootUsed = null, rootTotal = null;
            if (live && crNsNum(m.disk_total) > 0 && crNsNum(m.disk_used) != null) { rootUsed = m.disk_used; rootTotal = m.disk_total; }
            else if (s && s.rootfs && crNsNum(s.rootfs.total) > 0 && crNsNum(s.rootfs.used) != null) { rootUsed = s.rootfs.used; rootTotal = s.rootfs.total; }
            const root = rootTotal ? rootUsed * 100 / rootTotal : null;
            let swap = null, noSwap = false, swapUsed = null, swapTotal = null;
            if (s && s.swap && crNsNum(s.swap.total) != null) {
                if (s.swap.total > 0 && crNsNum(s.swap.used) != null) { swapUsed = s.swap.used; swapTotal = s.swap.total; swap = swapUsed * 100 / swapTotal; }
                else if (s.swap.total === 0) noSwap = true;
            }
            const judge = (id, v, key) => {
                if (v == null) { missing.push(id); return; }
                if (v > CR_CRIT) add(id, 'critical', key, { v: v.toFixed(1), lim: CR_CRIT });
                else if (v > CR_WARN) add(id, 'warning', key, { v: v.toFixed(1), lim: CR_WARN });
            };
            judge('cpu', cpu, 'crNsCpuHigh');
            judge('mem', mem, 'crNsMemHigh');
            if (!noSwap) judge('swap', swap, 'crNsSwapHigh');
            // LW Nov 2026 - the root disk is storage: the storage pair of the preview (crStoreTone)
            if (root == null) missing.push('root');
            else if (crStoreTone(root) !== 'success') {
                add('root', crStoreTone(root) === 'error' ? 'critical' : 'warning', 'crNsRootHigh',
                    { v: root.toFixed(1), lim: crStoreTone(root) === 'error' ? CR_STORE_CRIT : CR_STORE_WARN, warn: CR_STORE_WARN, crit: CR_STORE_CRIT });
            }

            const la = s && Array.isArray(s.loadavg) ? s.loadavg : (live && Array.isArray(m.loadavg) ? m.loadavg : null);
            const load = la ? [0, 1, 2].map(i => crNsNum(la[i])) : null;
            const cpus = crNsNum(s && s.cpuinfo && s.cpuinfo.cpus) || (live ? crNsNum(m.cpuinfo && m.cpuinfo.cpus) : null);
            const loadBad = !!la && load[0] == null;
            if (!la) missing.push('load');
            else if (load[0] != null && cpus > 0 && load[0] > cpus) add('load', 'warning', 'crNsLoadHigh', { v: load[0].toFixed(2), n: cpus });

            const upS = s ? crNsNum(s.uptime) : null;
            const up = upS > 0 ? upS : (live && crNsNum(m.uptime) > 0 ? m.uptime : null);
            if (up == null) missing.push('uptime');
            else if (up < 3600) add('uptime', 'info', 'crNsRecent', { t: crUptime(up) });

            const hwm = crNsHardware(hw, node);
            if (hwm.state === 'critical' || hwm.state === 'warning') {
                const more = hwm.names.length > 3 ? ` +${hwm.names.length - 3}` : '';
                add('hw', hwm.state, hwm.bad ? 'crNsHwItem' : 'crNsHwItemBmc', { n: hwm.bad, list: hwm.names.slice(0, 3).join(', ') + more });
            } else if (hwm.state === 'unread') missing.push('hwUnread');
            else if (hwm.state === 'none') missing.push('hw');

            const al = crNsAlerts(alerts, node, now);
            if (al.state === 'ok' && al.n > 0) {
                const level = al.sev.critical ? 'critical' : al.sev.warning ? 'warning' : 'info';
                add('alerts', level, 'crNsAlertsItem', { n: al.n, c: al.sev.critical, w: al.sev.warning });
            } else if (al.state !== 'ok') missing.push(al.state === 'error' ? 'alertsFailed' : al.state === 'old' ? 'alertsOld' : 'alerts');

            items.sort((a, b) => (CR_NS_RANK[b.level] || 0) - (CR_NS_RANK[a.level] || 0));
            const worst = items.reduce((w, it) => Math.max(w, it.level === 'info' ? 0 : (CR_NS_RANK[it.level] || 0)), 0);
            // a read that failed, or an alert read too old to stand for now, is not "no warning": what
            // it would say is not known. A source simply not read yet is listed below and leaves the badge
            const failed = sum === 'error' || sum === 'empty' || al.state === 'error' || al.state === 'old'
                || hwm.lm === 'error' || hwm.inband === 'error';
            const overall = worst === 3 ? 'critical' : worst === 2 ? 'warning'
                : (live && cpu != null && mem != null && !failed) ? 'normal' : 'unknown';
            const hwAge = hwm.at != null ? Math.max(0, now - hwm.at) : null;
            const alAge = al.at != null ? Math.max(0, now - al.at) : null;
            const ksm = live && s && s.ksm ? crNsNum(s.ksm.shared) : null;
            return { state, sum, cpu, mem, memUsed, memTotal, ksm, swap, noSwap, swapUsed, swapTotal, root, rootUsed, rootTotal,
                     load, loadBad, cpus, up, hw: hwm, alerts: al, items, missing, overall, failed, hwAge, alAge };
        }

        // --- tasks --------------------------------------------------------------------------------

        const CR_NT_STATES = ['ok', 'running', 'warning', 'failed'];
        const CR_NT_TONE = { ok: 'success', running: 'info', warning: 'warning', failed: 'error' };
        const CR_NT_LABEL = { ok: 'crNtStOk', running: 'crNtStRunning', warning: 'crNtStWarning', failed: 'crNtStFailed' };

        // XCP-ng says completed or failed: the task center's reading of it (cr_tasks.js)
        function crNtState(task, kind) {
            if (!task || typeof task !== 'object') return 'failed';
            if (kind && kind !== 'proxmox') {
                const s = crTaskState(task);
                if (s === 'running' || s === 'queued') return 'running';
                if (s === 'done') return crTaskWarned(task) ? 'warning' : 'ok';
                return 'failed';
            }
            if (!task.endtime && !task._ended) return 'running';
            const st = task.status == null ? '' : String(task.status).trim();
            if (st === 'OK') return 'ok';
            if (/^WARNINGS: \d+/.test(st)) return 'warning';
            return 'failed';
        }

        // the search: task type, UPID and user
        function crNtMatch(task, q) {
            const s = String(q || '').trim().toLowerCase();
            if (!s) return true;
            return ['type', 'upid', 'user'].some(k => task && task[k] != null && String(task[k]).toLowerCase().includes(s));
        }

        function crNtDur(start, end) {
            if (!start) return '-';
            const d = Math.max(0, Math.floor((end || Date.now() / 1000) - start));
            const h = Math.floor(d / 3600), m = Math.floor((d % 3600) / 60), sec = d % 60;
            return h > 0 ? `${h}h ${m}m ${sec}s` : m > 0 ? `${m}m ${sec}s` : `${sec}s`;
        }

        // --- guests -------------------------------------------------------------------------------

        const crNgStatus = (g) => (g.status === 'running' ? 'running' : g.status === 'stopped' ? 'stopped' : 'other');
        function crNgMatch(g, { type, status, q }) {
            if (type && type !== 'all' && g.type !== type) return false;
            if (status && status !== 'all' && crNgStatus(g) !== status) return false;
            const s = String(q || '').trim().toLowerCase();
            if (!s) return true;
            const tags = String(g.tags || '').split(/[;,\s]+/).filter(Boolean);
            return [g.name, g.vmid, g.ip, ...tags].some(v => v != null && String(v).toLowerCase().includes(s));
        }
        // what the agent column says: only a running VM has an agent that answers or not, and only
        // where the IP sweep set agent_running
        function crNgAgent(g) {
            if (g.type !== 'qemu') return 'ct';
            if (g.status !== 'running') return 'off';
            return typeof g.agent_running === 'boolean' ? (g.agent_running ? 'up' : 'down') : 'unknown';
        }

        window.PegaProxNodeSum = Object.freeze({ model: crNsModel, taskState: crNtState, taskMatch: crNtMatch,
                                                 guestMatch: crNgMatch, guestAgent: crNgAgent });

        // --- the summary ------------------------------------------------------------------------

        // how long ago a read came, from a minute on (a fresh one needs no word)
        function crNsAgo(t, ms) {
            if (ms == null || ms < 60000) return '';
            const min = Math.floor(ms / 60000);
            return min < 60 ? crNnT(t, 'crNsReadMin', { n: min }) : crNnT(t, 'crNsReadHours', { n: Math.floor(min / 60) });
        }

        function CrNodeHealth({ node, clusterId, metrics, summary, hw, loading, onPerf, onHardware, onReload }) {
            const { t } = useTranslation();
            const seen = crUseAlertsSeen(clusterId);
            const m = crNsModel({ metrics, summary, hw, alerts: seen, node, now: Date.now() });
            const nr = <span className="cr-muted cr-nh-none cr-ns-soft">{t('crNsNotReported')}</span>;
            const tone = (v, store) => { const x = store ? crStoreTone(v) : crTone(v); return x === 'error' || x === 'warning' ? x : undefined; };
            const level = (id) => { const it = m.items.find(i => i.id === id && i.level !== 'info'); return it ? (it.level === 'critical' ? 'error' : 'warning') : undefined; };
            const ov = { critical: ['error', 'crNsOvCritical'], warning: ['warning', 'crNsOvWarning'],
                         normal: ['success', 'crNsOvNormal'], unknown: ['neutral', 'crNsOvUnknown'] }[m.overall];
            const hwLabel = { critical: 'crNhOverallCritical', warning: 'crNhOverallWarning', normal: 'crNhOverallNormal', none: 'crNhOverallNone' };
            const missLabel = { status: t('status'), cpu: t('cpu'), mem: t('memory'), swap: t('swap'), root: t('crNsRoot'),
                                load: t('crNsLoad'), uptime: t('uptime'), hw: t('hardware'), hwUnread: t('crNsMissHwUnread'),
                                alerts: t('crNsMissAlerts'), alertsFailed: t('crNsMissAlertsFailed'), alertsOld: t('crNsMissAlertsOld') };
            const pct = (v) => `${v.toFixed(1)}%`;
            const loadSub = m.load ? crNnT(t, m.cpus ? 'crNsLoadSub' : 'crNsLoadSubNoCpus', {
                b: m.load[1] != null ? m.load[1].toFixed(2) : '-', c: m.load[2] != null ? m.load[2].toFixed(2) : '-', n: m.cpus || '' }) : '';
            const al = m.alerts;
            const hwSub = m.hw.state === 'unread' ? t('crNsHwUnreadSub') : [
                m.hw.total ? crNnT(t, 'crNhJudged', { j: m.hw.judged, n: m.hw.total }) : '',
                m.hw.lmUnread ? t('crNsHwLmUnread') : '', m.hw.inbandUnread ? t('crNsHwInbandUnread') : '',
                crNsAgo(t, m.hwAge)].filter(Boolean).join(', ');
            return (
                <CrNcSection id="health" className="cr-ns" data-cr-ns="" data-cr-ns-overall={m.overall} aria-label={t('crNsTitle')}
                    title={t('crNsTitle')} desc={t('crNcHealthDesc')}
                    badge={(
                        <span data-cr-ns-badge="" title={m.overall === 'normal' ? t('crNsOvNormalHint') : undefined}>
                            <CrBadge tone={ov[0]} dot={ov[0] !== 'neutral'}>{t(ov[1])}</CrBadge>
                        </span>
                    )}>
                    <div className="cr-stat-row cr-ns-tiles" data-cr-ns-tiles="">
                        <CrStat id="ns-cpu" label={t('cpu')} value={m.cpu != null ? pct(m.cpu) : nr} meter={m.cpu != null ? m.cpu : null}
                            tone={tone(m.cpu)} sub={m.cpus ? crNnT(t, 'crNsCpuSub', { n: m.cpus }) : ''} onClick={onPerf} title={t('crNsToPerf')} />
                        <CrStat id="ns-mem" label={t('memory')} value={m.mem != null ? pct(m.mem) : nr} meter={m.mem != null ? m.mem : null}
                            tone={tone(m.mem)} onClick={onPerf} title={t('crNsToPerf')}
                            sub={m.mem != null ? `${formatBytes(m.memUsed)} / ${formatBytes(m.memTotal)}${m.ksm != null ? crNnT(t, 'crNsKsm', { v: formatBytes(m.ksm) }) : ''}` : ''} />
                        <CrStat id="ns-swap" label={t('swap')} value={m.noSwap ? t('crNsSwapNone') : m.swap != null ? pct(m.swap) : nr}
                            meter={m.swap != null ? m.swap : null} tone={tone(m.swap)}
                            sub={m.noSwap ? t('crNsSwapNoneSub') : m.swap != null ? `${formatBytes(m.swapUsed)} / ${formatBytes(m.swapTotal)}` : ''} />
                        <CrStat id="ns-root" label={t('crNsRoot')} value={m.root != null ? pct(m.root) : nr} meter={m.root != null ? m.root : null}
                            meterTone={m.root != null ? crStoreTone(m.root) : undefined} title={crStoreScale(t)}
                            tone={tone(m.root, true)} sub={m.root != null ? `${formatBytes(m.rootUsed)} / ${formatBytes(m.rootTotal)}` : ''} />
                        <CrStat id="ns-load" label={t('crNsLoad')} tone={level('load')}
                            value={m.loadBad ? <span className="cr-nh-bad cr-ns-soft">{t('crNhUnreadable')}</span> : m.load && m.load[0] != null ? m.load[0].toFixed(2) : nr}
                            sub={loadSub} />
                        <CrStat id="ns-uptime" label={t('uptime')} value={m.up != null ? crUptime(m.up) : nr}
                            sub={m.up != null && m.up < 3600 ? t('crNsRecentSub') : ''} />
                        {m.hw.state !== 'na' && (
                            <CrStat id="ns-hw" label={t('hardware')} onClick={onHardware} title={t('crNsToHw')}
                                tone={m.hw.state === 'critical' ? 'error' : m.hw.state === 'warning' ? 'warning' : undefined}
                                value={m.hw.state === 'unread' ? <span className="cr-muted cr-ns-soft">{t('crNsHwUnread')}</span>
                                    : m.hw.state === 'none' ? <span className="cr-muted cr-ns-soft">{t(hwLabel.none)}</span> : t(hwLabel[m.hw.state])}
                                sub={hwSub} />
                        )}
                        <CrStat id="ns-alerts" label={t('crNsAlerts')}
                            tone={al.state === 'ok' && al.sev.critical ? 'error' : al.state === 'ok' && al.sev.warning ? 'warning' : undefined}
                            value={al.state === 'ok' ? String(al.n) : <span className="cr-muted cr-ns-soft">{t(al.state === 'error' ? 'crNsAlertsFailed' : 'crNsAlertsUnread')}</span>}
                            sub={al.state === 'ok' ? (al.acked ? crNnT(t, 'crNsAlertsAcked', { n: al.acked }) : '') : al.state === 'unread' ? t('crNsAlertsUnreadSub')
                                : al.state === 'old' ? crNsAgo(t, m.alAge) : ''} />
                    </div>
                    {m.items.length > 0 && (
                        <ul className="cr-ns-items" aria-label={t('crNsConditions')}>
                            {m.items.map(it => (
                                <li key={it.id} className={`cr-ns-item cr-ns-${it.level}`} data-cr-ns-item={it.id} data-cr-ns-level={it.level}>
                                    {it.level === 'info' ? <Icons.Info className="w-3.5 h-3.5" /> : <Icons.AlertTriangle className="w-3.5 h-3.5" />}
                                    <span>{crNnT(t, it.key, it.vars)}</span>
                                </li>
                            ))}
                        </ul>
                    )}
                    {m.sum !== 'ok' && (
                        m.sum === 'loading' ? (
                            <p className="cr-nn-mgmt-line" data-cr-ns-sum="loading">
                                <span className="cr-nh-srcline"><Icons.RotateCw className="w-3.5 h-3.5 animate-spin" /> {t('crNsSumReading')}</span>
                            </p>
                        ) : (
                            <div className="cr-callout cr-callout-warning" role="status" data-cr-ns-sum={m.sum}>
                                <Icons.AlertTriangle className="w-4 h-4" />
                                <div><p>{t(m.sum === 'error' ? 'crNsSumFailed' : 'crNsSumEmpty')}</p></div>
                                <button type="button" className="cr-btn cr-btn-xs" onClick={onReload} disabled={loading} data-cr-ns-retry="">{t('retry')}</button>
                            </div>
                        )
                    )}
                    {m.missing.length > 0 && (
                        <p className="cr-nn-mgmt-line" data-cr-ns-missing={m.missing.join(' ')}>
                            {crNnT(t, 'crNsMissing', { list: m.missing.map(k => missLabel[k] || k).join(', ') })}
                        </p>
                    )}
                    <p className="cr-muted cr-ns-basis">{crNnT(t, 'crNsBasis', { warn: CR_WARN, crit: CR_CRIT, swarn: CR_STORE_WARN, scrit: CR_STORE_CRIT })}</p>
                </CrNcSection>
            );
        }

        // --- the tasks sub tab ------------------------------------------------------------------

        // the open task: its log (the task center's reader), and while it runs its status every 2 s,
        // so the row ends when the task does; then the list is read again for the end time
        function CrNtLog({ row, kind, authFetch, onEnded, onClose, t }) {
            const log = crUseTaskLog(row, true, authFetch, t);
            const st = crNtState(row, kind);
            const [statusFail, setStatusFail] = useState(false);
            const running = st === 'running' && kind === 'proxmox';
            useEffect(() => {
                setStatusFail(false);
                if (!running || !authFetch) return undefined;
                let gone = false, timer = null;
                const url = `${API_URL}/clusters/${row.cluster_id}/nodes/${row.node}/tasks/${encodeURIComponent(row.upid)}/status`;
                const beat = async () => {
                    const r = await authFetch(url);
                    if (gone) return;
                    const d = r && r.ok ? await r.json().catch(() => null) : null;
                    if (gone) return;
                    if (!d || typeof d.status !== 'string') { setStatusFail(true); return; }
                    if (d.status === 'stopped') { onEnded(row.upid, d.exitstatus); return; }
                    timer = setTimeout(beat, CR_TC.logEvery);
                };
                timer = setTimeout(beat, CR_TC.logEvery);
                return () => { gone = true; clearTimeout(timer); };
            }, [row.upid, running]);
            const title = `${row.type || '-'}${row.id ? ` (${row.id})` : ''}`;
            return (
                <div className="cr-nt-log" data-cr-nt-log={row.upid} data-cr-nt-log-state={st}>
                    <CrTaskLogPane row={row} log={log} title={title} fmt={crNtDur} onClose={onClose} t={t}
                        mark={{ tone: CR_NT_TONE[st], label: t(CR_NT_LABEL[st]) }} />
                    {statusFail && <p className="cr-muted cr-ns-basis" data-cr-nt-status-fail="">{t('crNtStatusFail')}</p>}
                </div>
            );
        }

        function CrNodeTasks({ node, clusterId, kind, read, loading, authFetch, onReload, guests, onOpenGuest }) {
            const { t } = useTranslation();
            const [f, setF] = useState('all');
            const [q, setQ] = useState('');
            const [openId, setOpenId] = useState(null);
            const [ended, setEnded] = useState({});
            const fail = crNdFail(read);
            const list = !fail && Array.isArray(read) ? read : null;
            const bad = read !== undefined && !fail && !list;
            const rows = useMemo(() => (list || []).filter(r => r && typeof r === 'object').map(r => {
                const over = ended[r.upid];
                return { ...r, ...(over && !r.endtime ? over : {}), node: r.node || node, cluster_id: clusterId };
            }), [list, ended, node, clusterId]);
            const stateOf = (r) => crNtState(r, kind);
            const counts = useMemo(() => {
                const c = { all: rows.length, ok: 0, running: 0, warning: 0, failed: 0 };
                rows.forEach(r => { c[crNtState(r, kind)]++; });
                return c;
            }, [rows, kind]);
            const byId = useMemo(() => {
                const mp = new Map();
                (guests || []).forEach(g => mp.set(String(g.vmid), g));
                return mp;
            }, [guests]);
            const filter = useCallback((r) => (f === 'all' || crNtState(r, kind) === f) && crNtMatch(r, q), [f, q, kind]);
            const open = openId ? rows.find(r => r.upid === openId) || null : null;
            const onEnded = (upid, exit) => {
                setEnded(prev => ({ ...prev, [upid]: { status: exit == null ? '' : String(exit), _ended: true } }));
                onReload();
            };
            const columns = useMemo(() => [
                { key: 'state', label: t('status'), width: 92, sortValue: r => CR_NT_STATES.indexOf(stateOf(r)),
                  render: r => {
                      const s = stateOf(r);
                      return <span data-cr-nt-row={r.upid} data-cr-nt-state={s}><CrBadge tone={CR_NT_TONE[s]}>{t(CR_NT_LABEL[s])}</CrBadge></span>;
                  } },
                { key: 'type', label: t('type'), width: 96, render: r => <span className="cr-strong">{r.type || '-'}</span> },
                { key: 'guest', label: t('crNtGuest'), width: 112, sortValue: r => (r.id ? String(r.id) : null),
                  render: r => {
                      if (!r.id) return <span className="cr-muted">-</span>;
                      const g = byId.get(String(r.id));
                      if (!g || !onOpenGuest) return <span>{r.id}</span>;
                      const name = g.name || String(g.vmid);
                      return (
                          <button type="button" className="cr-tc-link" tabIndex={-1} data-cr-nt-guest={r.id}
                              title={crNnT(t, 'crNtOpenGuest', { name })}
                              onClick={e => { e.stopPropagation(); onOpenGuest(g); }}>{name} ({r.id})</button>
                      );
                  } },
                { key: 'user', label: t('user'), width: 92 },
                { key: 'starttime', label: t('startTime'), width: 160, mono: true, sortValue: r => r.starttime || null,
                  render: r => (r.starttime ? <span title={crDate(r.starttime)}>{crDate(r.starttime)}</span> : '') },
                { key: 'duration', label: t('duration'), width: 80, mono: true, align: 'right',
                  sortValue: r => (!r.starttime ? null : r.endtime ? r.endtime - r.starttime : stateOf(r) === 'running' ? Date.now() / 1000 - r.starttime : null),
                  render: r => <CrDuration task={r} fmt={crNtDur} /> },
                { key: 'result', label: t('crNtResult'), flex: true, min: 100, sortValue: r => (stateOf(r) === 'running' ? null : String(r.status || '')),
                  render: r => {
                      const s = stateOf(r);
                      if (s === 'running') return <span className="cr-muted">{t('crNtStillRunning')}</span>;
                      const text = String(r.status == null ? '' : r.status).trim();
                      if (!text) return <span className="cr-muted cr-nh-none">{t('crNtNoStatus')}</span>;
                      return <span className={`cr-tc-result cr-tc-result-${CR_NT_TONE[s]}`} title={text}>{text}</span>;
                  } },
                { key: 'upid', label: 'UPID', width: 220, mono: true, hidden: true, render: r => <span title={r.upid}>{r.upid}</span> },
            ], [t, kind, byId, onOpenGuest]);

            const active = (f !== 'all' ? 1 : 0) + (q.trim() ? 1 : 0);
            const err = fail ? crNnT(t, 'crNtFailed', { why: crNdWhy(t, fail) }) : bad ? crNnT(t, 'crNtFailed', { why: t('crNdNotJson') }) : null;
            const segs = [['all', t('all')], ...CR_NT_STATES.map(s => [s, t(CR_NT_LABEL[s])])];
            return (
                <div className="cr-nn cr-nt" data-cr-nt="" data-cr-nt-read={read === undefined ? 'loading' : err ? 'error' : rows.length ? 'ok' : 'empty'}>
                    <div className="cr-nn-bar">
                        <h3 className="cr-nn-title">{t('tasks')}</h3>
                        {list && <span className="cr-muted cr-nn-count" data-cr-nt-scope="">{crNnT(t, 'crNtScope', { n: rows.length, node })}</span>}
                        <div className="cr-nn-acts">
                            <CrButton icon={<Icons.RotateCw />} onClick={onReload} disabled={loading && read === undefined} data-cr-nt-reload="">{t('refresh')}</CrButton>
                        </div>
                    </div>
                    {err && (
                        <div className="cr-callout cr-callout-warning" role="status" data-cr-nt-error="">
                            <Icons.AlertTriangle className="w-4 h-4" />
                            <div><p>{err}</p></div>
                            <button type="button" className="cr-btn cr-btn-xs" onClick={onReload} disabled={loading} data-cr-nt-retry="">{t('retry')}</button>
                        </div>
                    )}
                    {counts.failed > 0 && (
                        <div className="cr-callout cr-callout-error" role="status" data-cr-nt-failed-note={counts.failed}>
                            <Icons.AlertTriangle className="w-4 h-4" />
                            <div><p>{crNnT(t, 'crNtFailedSome', { n: counts.failed, m: rows.length })}</p></div>
                            {f !== 'failed' && (
                                <button type="button" className="cr-btn cr-btn-xs" onClick={() => setF('failed')} data-cr-nt-show-failed="">{t('crNtShowFailed')}</button>
                            )}
                        </div>
                    )}
                    <CrTable id="node-tasks" columns={columns} rows={rows} filter={filter} rowKey={r => r.upid || ''}
                        selectedKey={open ? open.upid : undefined} onRowClick={r => setOpenId(r.upid)} ariaLabel={t('tasks')}
                        rowClassName={r => { const s = stateOf(r); return s === 'failed' ? 'cr-nt-row-failed' : s === 'warning' ? 'cr-nt-row-warn' : ''; }}
                        loading={read === undefined} error={err}
                        emptyText={crNnT(t, 'crNtEmpty', { node })} maxHeight={open ? 300 : 520}
                        toolbar={(
                            <div className="cr-tc-filters cr-nt-filters">
                                <div className="cr-seg" role="group" aria-label={t('status')} data-cr-nt-strip="">
                                    {segs.map(([id, label]) => (
                                        <button key={id} type="button" className={`${f === id ? 'active' : ''}${id === 'failed' && counts.failed ? ' cr-nt-seg-failed' : ''}`}
                                            aria-pressed={f === id} data-cr-nt-filter={id} onClick={() => setF(id)}>
                                            {label}<span className="cr-seg-n" data-cr-nt-count={id}>{list ? counts[id] : '-'}</span>
                                        </button>
                                    ))}
                                </div>
                                <div className="cr-search-box">
                                    <Icons.Search className="cr-search-ico" />
                                    <input type="search" className="cr-input" value={q} data-cr-nt-q="" placeholder={t('crNtSearch')}
                                        aria-label={t('crNtSearch')} onChange={e => setQ(e.target.value)} />
                                </div>
                                {active > 0 && (
                                    <button type="button" className="cr-btn cr-btn-ghost" data-cr-nt-clear="" onClick={() => { setF('all'); setQ(''); }}>
                                        {t('crNgClear')}
                                    </button>
                                )}
                            </div>
                        )} />
                    {open && (
                        <CrNtLog key={open.upid} row={open} kind={kind} authFetch={authFetch} onEnded={onEnded} onClose={() => setOpenId(null)} t={t} />
                    )}
                </div>
            );
        }

        // --- the guests tab ---------------------------------------------------------------------

        function CrNodeGuests({ node, guests, onSelectVm }) {
            const { t } = useTranslation();
            const [type, setType] = useState('all');
            const [status, setStatus] = useState('all');
            const [q, setQ] = useState('');
            const rows = Array.isArray(guests) ? guests : [];
            const counts = useMemo(() => {
                const c = { all: rows.length, qemu: 0, lxc: 0, running: 0, stopped: 0, other: 0 };
                rows.forEach(g => { if (g.type === 'qemu' || g.type === 'lxc') c[g.type]++; c[crNgStatus(g)]++; });
                return c;
            }, [rows]);
            const filter = useCallback((g) => crNgMatch(g, { type, status, q }), [type, status, q]);
            const agentText = { up: t('crNgAgentUp'), down: t('crNgAgentDown'), unknown: t('listColAgentUnknown'), ct: t('crNgAgentCt'), off: '-' };
            const columns = useMemo(() => [
                { key: 'name', label: t('name'), flex: true, min: 170, sortValue: g => g.name || null,
                  render: g => (
                      <span className="cr-ng-name" data-cr-ng-row={g.vmid} data-cr-ng-type={g.type}>
                          <span className="cr-ico cr-muted" aria-hidden="true">{g.type === 'lxc' ? <Icons.Box /> : <Icons.Monitor />}</span>
                          <span className="cr-strong">{g.name || <span className="cr-muted">{t('crNgNoName')}</span>}</span>
                          {!!g.template && <CrBadge tone="neutral" dot={false}>{t('crNgTemplate')}</CrBadge>}
                      </span>
                  ) },
                { key: 'vmid', label: 'ID', width: 76, mono: true, sortValue: g => crNsNum(g.vmid) },
                { key: 'type', label: t('type'), width: 64, sortValue: g => g.type, render: g => (g.type === 'lxc' ? t('crNgCt') : g.type === 'qemu' ? t('crNgVm') : g.type) },
                { key: 'status', label: t('status'), width: 136, sortValue: g => g.status || null,
                  render: g => (
                      <span className="cr-ng-status" data-cr-ng-status={g.status || ''}>
                          <CrStateBadge state={g.status} />
                          {g.lock && <span className="cr-muted cr-ng-lock">{crNnT(t, 'crNgLocked', { lock: g.lock })}</span>}
                      </span>
                  ) },
                { key: 'cpu', label: t('cpu'), width: 128, sortValue: g => (g.status === 'running' && crNsNum(g.cpu) != null ? g.cpu * 100 : null),
                  render: g => (g.status === 'running' && crNsNum(g.cpu) != null
                      ? <span data-cr-ng-cpu={(g.cpu * 100).toFixed(1)}><CrMeter value={g.cpu * 100} digits={1}
                            title={g.maxcpu ? crNnT(t, 'crNgCpuHint', { v: (g.cpu * 100).toFixed(1), n: g.maxcpu }) : undefined} /></span>
                      : <span className="cr-muted">-</span>) },
                { key: 'mem', label: t('memory'), width: 160, sortValue: g => (g.status === 'running' && crNsNum(g.mem) != null ? g.mem : null),
                  render: g => (g.status === 'running' && crNsNum(g.mem) != null && g.maxmem > 0
                      ? <span data-cr-ng-mem={g.mem} title={crNnT(t, 'crNgMemHint', { v: (g.mem * 100 / g.maxmem).toFixed(1) })}>{formatBytes(g.mem)} / {formatBytes(g.maxmem)}</span>
                      : <span className="cr-muted">-</span>) },
                { key: 'agent', label: t('listColAgent'), width: 124, title: t('listColAgentHint'), sortValue: g => crNgAgent(g),
                  render: g => {
                      const a = crNgAgent(g);
                      return (
                          <span data-cr-ng-agent={a}>
                              {a === 'up' ? <CrBadge tone="success">{agentText.up}</CrBadge>
                                  : a === 'off' ? <span className="cr-muted">-</span>
                                  : <span className="cr-muted">{agentText[a]}</span>}
                          </span>
                      );
                  } },
                { key: 'uptime', label: t('uptime'), width: 92, mono: true, sortValue: g => (g.status === 'running' && g.uptime > 0 ? g.uptime : null),
                  render: g => (g.status === 'running' && g.uptime > 0 ? crUptime(g.uptime) : <span className="cr-muted">-</span>) },
            ], [t]);
            const active = (type !== 'all' ? 1 : 0) + (status !== 'all' ? 1 : 0) + (q.trim() ? 1 : 0);
            const seg = (val, set, list, attr) => (
                <div className="cr-seg" role="group" {...{ [attr]: '' }}>
                    {list.map(([id, label]) => (
                        <button key={id} type="button" className={val === id ? 'active' : ''} aria-pressed={val === id}
                            data-cr-ng-filter={id} onClick={() => set(id)}>
                            {label}<span className="cr-seg-n">{counts[id]}</span>
                        </button>
                    ))}
                </div>
            );
            return (
                <div className="cr-nn cr-ng" data-cr-ng="">
                    <div className="cr-nn-bar">
                        <h3 className="cr-nn-title">{crNnT(t, 'crNgTitle', { node })}</h3>
                    </div>
                    <CrTable id="node-guests" columns={columns} rows={rows} filter={filter} rowKey={g => String(g.vmid)}
                        onRowClick={onSelectVm ? (g => onSelectVm(g)) : undefined} ariaLabel={crNnT(t, 'crNgTitle', { node })}
                        initialSort={{ key: 'name', dir: 'asc' }} emptyText={crNnT(t, 'crNgEmpty', { node })} maxHeight={560}
                        toolbar={(
                            <div className="cr-tc-filters cr-nt-filters">
                                {seg(type, setType, [['all', t('all')], ['qemu', t('crNgVm')], ['lxc', t('crNgCt')]], 'data-cr-ng-types')}
                                {seg(status, setStatus, [['all', t('all')], ['running', t('running')], ['stopped', t('crNgStopped')], ['other', t('crNgOther')]], 'data-cr-ng-states')}
                                <div className="cr-search-box">
                                    <Icons.Search className="cr-search-ico" />
                                    <input type="search" className="cr-input" value={q} data-cr-ng-q="" placeholder={t('crNgSearch')}
                                        aria-label={t('crNgSearch')} onChange={e => setQ(e.target.value)} />
                                </div>
                                {active > 0 && (
                                    <button type="button" className="cr-btn cr-btn-ghost" data-cr-ng-clear=""
                                        onClick={() => { setType('all'); setStatus('all'); setQ(''); }}>{t('crNgClear')}</button>
                                )}
                            </div>
                        )} />
                </div>
            );
        }
