        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned: blueprints of the template library - LW Nov 2026 (#1220)
        // A blueprint is an image of the library with hardware and Cloud-Init settings, kept on the
        // server for every account. A deploy puts a guest from it on any Proxmox VE cluster in one
        // step: the server reuses a template it built from that image there (or builds one first),
        // clones it and applies the rest. The page reads the blueprints and the recent deploys of
        // this cluster once; the library images, nodes, storages and the next VMID only when a dialog
        // asks for them, and the progress of a deploy only while its dialog is open.
        // ═══════════════════════════════════════════════════════════

        const CR_BP_MODELS = ['virtio', 'e1000', 'vmxnet3', 'rtl8139'];
        const CR_BP_IP_MODES = ['dhcp', 'static', 'none'];
        const CR_BP_IP_WORD = { dhcp: 'crBpIpDhcp', static: 'crBpIpStatic', none: 'crBpIpNone' };
        const CR_BP_MAX_NICS = 4;
        // the ranges the server takes (memory in MB, disk in GB; disk 0 keeps the image size)
        const CR_BP_LIMITS = { cores: [1, 512], memory: [64, 4194304], disk_gb: [0, 65536], vlan: [1, 4094], vmid: [100, 999999999] };
        const CR_BP_POLL = 2500;
        const CR_BP_STEPS = ['template', 'clone', 'configure', 'resize', 'start', 'done'];
        const CR_BP_STEP_WORD = { template: 'crBpStepTemplate', clone: 'crBpStepClone', configure: 'crBpStepConfigure',
                                  resize: 'crBpStepResize', start: 'crBpStepStart', done: 'crBpStepDone' };
        const CR_BP_STATE_TONE = { queued: 'neutral', running: 'info', completed: 'success', failed: 'error' };
        const CR_BP_STATE_WORD = { queued: 'crBpStQueued', running: 'crBpStRunning', completed: 'crBpStCompleted', failed: 'crBpStFailed' };
        // a bridge, node or storage name as the server checks it; a VM name as PVE takes it
        const CR_BP_NAME_RE = /^[A-Za-z0-9._-]+$/;
        const CR_BP_VMNAME_RE = /^[A-Za-z0-9][A-Za-z0-9.-]*$/;
        // a group after each dash: the arbitrary-class scan of the Tailwind check reads a dash and a bracket as a class
        const CR_BP_KEY_RE = /^(ssh-(?:[a-z0-9-]+)|ecdsa-sha2-(?:[a-z0-9-]+)|sk-(?:[a-z0-9@.-]+))\s+\S+/;
        const crBpLive = (s) => s === 'queued' || s === 'running';

        // a whole number typed into a field, NaN for anything else
        const crBpInt = (v) => (/^\s*\d+\s*$/.test(String(v == null ? '' : v)) ? parseInt(v, 10) : NaN);
        const crBpIn = (n, [lo, hi]) => Number.isInteger(n) && n >= lo && n <= hi;

        function crBpIsIp4(v) {
            const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(v || '').trim());
            return !!m && m.slice(1).every(p => Number(p) <= 255 && String(Number(p)) === p);
        }
        function crBpIsIp6(v) {
            const s = String(v || '').trim();
            if (!/^[0-9a-fA-F:]+$/.test(s) || !s.includes(':') || (s.match(/::/g) || []).length > 1) return false;
            const parts = s.split(':');
            return parts.length <= 8 && parts.every(p => p.length <= 4);
        }
        const crBpIsIp = (v) => crBpIsIp4(v) || crBpIsIp6(v);
        // an address with its prefix: 10.0.0.5/24 or 2001:db8::5/64
        function crBpIsCidr(v) {
            const [addr, len, more] = String(v || '').trim().split('/');
            if (more !== undefined || len === undefined || !/^\d{1,3}$/.test(len)) return false;
            if (crBpIsIp4(addr)) return Number(len) <= 32;
            return crBpIsIp6(addr) && Number(len) <= 128;
        }
        // the ipconfig0 of a static address, as PVE takes it (ip6/gw6 for an IPv6 address)
        function crBpIpconfig(ip, gw) {
            const a = String(ip || '').trim();
            const g = String(gw || '').trim();
            const six = a.includes(':');
            return `${six ? 'ip6' : 'ip'}=${a}${g ? `,${six ? 'gw6' : 'gw'}=${g}` : ''}`;
        }

        const crBpNic = () => ({ bridge: 'vmbr0', vlan: '', model: 'virtio', firewall: false });

        // the editor's form of a blueprint (or of a new one): strings as typed, memory in GB when whole
        function crBpForm(bp) {
            if (!bp) {
                return { name: '', description: '', template_id: '', cores: '2', memory: '2', memUnit: 'GB', disk_gb: '0', cpu: '',
                         nics: [crBpNic()], ciuser: '', sshkeys: '', ip_mode: 'dhcp', nameserver: '', searchdomain: '',
                         ciupgrade: false, tags: '', start: true };
            }
            const mem = Number(bp.memory) || 0;
            const gb = mem > 0 && mem % 1024 === 0;
            const nics = Array.isArray(bp.nics) && bp.nics.length ? bp.nics : [crBpNic()];
            return {
                name: bp.name || '', description: bp.description || '', template_id: bp.template_id || '',
                cores: String(bp.cores ?? ''), memory: String(gb ? mem / 1024 : mem), memUnit: gb ? 'GB' : 'MB',
                disk_gb: String(bp.disk_gb ?? 0), cpu: bp.cpu || '',
                nics: nics.map(n => ({ bridge: (n && n.bridge) || '', vlan: n && n.vlan != null ? String(n.vlan) : '',
                                       model: CR_BP_MODELS.includes(n && n.model) ? n.model : 'virtio', firewall: !!(n && n.firewall) })),
                ciuser: bp.ciuser || '', sshkeys: bp.sshkeys || '', ip_mode: CR_BP_IP_MODES.includes(bp.ip_mode) ? bp.ip_mode : 'dhcp',
                nameserver: bp.nameserver || '', searchdomain: bp.searchdomain || '', ciupgrade: !!bp.ciupgrade,
                tags: Array.isArray(bp.tags) ? bp.tags.join(', ') : '', start: bp.start !== false,
            };
        }

        // the memory of the form in MB, NaN when it is no number
        function crBpMemMb(f) {
            const s = String(f.memory || '').trim().replace(',', '.');
            if (f.memUnit === 'GB') return /^\d+(\.\d+)?$/.test(s) ? Math.round(parseFloat(s) * 1024) : NaN;
            return crBpInt(s);
        }

        // the body POST and PUT /api/blueprints take: the editable fields of a blueprint
        function crBpBody(f) {
            return {
                name: f.name.trim(), description: f.description.trim(), template_id: f.template_id,
                cores: crBpInt(f.cores), memory: crBpMemMb(f), disk_gb: crBpInt(f.disk_gb), cpu: f.cpu.trim(),
                nics: f.nics.map(n => ({ bridge: n.bridge.trim(), vlan: String(n.vlan).trim() === '' ? null : crBpInt(n.vlan),
                                         model: n.model, firewall: !!n.firewall })),
                ciuser: f.ciuser.trim(), sshkeys: f.sshkeys.split('\n').map(l => l.trim()).filter(Boolean).join('\n'),
                ip_mode: f.ip_mode, nameserver: f.nameserver.trim(), searchdomain: f.searchdomain.trim(),
                ciupgrade: !!f.ciupgrade, tags: f.tags.split(',').map(s => s.trim()).filter(Boolean), start: !!f.start,
            };
        }

        // what keeps the form from being saved: field -> text
        function crBpCheck(f, t) {
            const e = {};
            const range = ([lo, hi]) => crFill(t('crBpErrRange'), { min: lo, max: hi });
            if (!f.name.trim()) e.name = t('crBpErrName');
            if (!f.template_id) e.template_id = t('crBpErrImage');
            if (!crBpIn(crBpInt(f.cores), CR_BP_LIMITS.cores)) e.cores = range(CR_BP_LIMITS.cores);
            if (!crBpIn(crBpMemMb(f), CR_BP_LIMITS.memory)) {
                e.memory = f.memUnit === 'GB' ? range(CR_BP_LIMITS.memory.map(v => Math.round(v / 1024 * 100) / 100)) : range(CR_BP_LIMITS.memory);
            }
            if (!crBpIn(crBpInt(f.disk_gb), CR_BP_LIMITS.disk_gb)) e.disk_gb = range(CR_BP_LIMITS.disk_gb);
            if (!f.nics.length || f.nics.length > CR_BP_MAX_NICS) e.nics = t('crBpErrNics');
            f.nics.forEach((n, i) => {
                if (!CR_BP_NAME_RE.test(n.bridge.trim())) e[`nic${i}-bridge`] = t('crBpErrBridge');
                if (String(n.vlan).trim() !== '' && !crBpIn(crBpInt(n.vlan), CR_BP_LIMITS.vlan)) e[`nic${i}-vlan`] = t('crBpErrVlan');
            });
            return e;
        }

        // the lines of the key field that do not look like an SSH public key (1-based)
        function crBpOddKeys(text) {
            return String(text || '').split('\n').map((l, i) => [l.trim(), i + 1])
                .filter(([l]) => l && !l.startsWith('#') && !CR_BP_KEY_RE.test(l)).map(([, n]) => n);
        }

        // a VM name proposed from the blueprint name
        function crBpVmName(name) {
            const s = String(name || '').toLowerCase().replace(/[^a-z0-9.-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 50);
            return s || 'vm';
        }

        function crBpHw(bp, t) {
            const mem = Number(bp.memory) || 0;
            const ram = mem >= 1024 && mem % 1024 === 0 ? `${mem / 1024} GB` : `${mem} MB`;
            const disk = Number(bp.disk_gb) > 0 ? `${bp.disk_gb} GB` : t('crBpDiskKeep');
            return `${bp.cores} vCPU · ${ram} · ${disk}`;
        }

        async function crBpSend(authFetch, url, method, body) {
            const r = await authFetch(url, { method, headers: { 'Content-Type': 'application/json' },
                                             body: body === undefined ? undefined : JSON.stringify(body) });
            if (!r) return { ok: false, code: 0, body: null };
            if (await haLeaderAway(r)) return { ok: false, code: 503, away: true, body: null };
            const data = await r.json().catch(() => null);
            return { ok: r.ok && !(data && data.error), code: r.status, body: data };
        }
        // the row of a deployment: its own `error` says why the deploy failed, not that the read did
        // (crDriftRead takes any body with an error as a failed read)
        async function crBpReadRow(authFetch, url) {
            const r = await authFetch(url);
            if (!r) return { state: 'offline' };
            if (await haLeaderAway(r)) return { state: 'away' };
            const body = await r.json().catch(() => null);
            if (r.ok && body && typeof body === 'object' && typeof body.status === 'string') return { state: 'ok', body };
            return { state: r.status === 429 ? 'limited' : 'error', code: r.status, msg: body && typeof body.error === 'string' ? body.error : '' };
        }
        const crBpSendText = (res, t) => (res.away ? t('crDriftOffline')
            : [res.body && typeof res.body.error === 'string' ? res.body.error : '', res.code ? `HTTP ${res.code}` : ''].filter(Boolean).join(' - ')
              || t('crLoadFailed'));

        // --- the parts -----------------------------------------------------------------------------

        function CrBpState({ state }) {
            const { t } = useTranslation();
            return <span data-cr-bp-state={state}><CrBadge tone={CR_BP_STATE_TONE[state] || 'neutral'}>{t(CR_BP_STATE_WORD[state] || 'crBpStQueued')}</CrBadge></span>;
        }

        // one input of a dialog with its label, its hint and the error of the check or of the server
        function CrBpField({ id, label, hint, error, wide, children }) {
            return (
                <CrNcField id={`bp-${id}`} label={label} wide={wide} hint={error || hint} hintTone={error ? 'error' : undefined}>
                    {children}
                </CrNcField>
            );
        }

        // The create and edit dialog. bp: the blueprint to edit, null for a new one. bridges: names
        // the bridge fields suggest (the network of one node of this cluster, read when it opens)
        function CrBpEditor({ bp, authFetch, bridges, onCancel, onSaved }) {
            const { t } = useTranslation();
            const [form, setForm] = useState(() => crBpForm(bp));
            const [cat, setCat] = useState({ state: 'loading', rows: [], why: '' });
            const [tried, setTried] = useState(false);
            const [busy, setBusy] = useState(false);
            const [server, setServer] = useState(null);
            useEffect(() => {
                let gone = false;
                crDriftRead(authFetch, `${API_URL}/templates/catalog`).then(read => {
                    if (gone) return;
                    if (read.state === 'ok') setCat({ state: 'ok', rows: Array.isArray(read.body.templates) ? read.body.templates : [], why: '' });
                    else setCat({ state: 'error', rows: [], why: crDriftReadText(read, t) });
                });
                return () => { gone = true; };
            }, []);
            const set = (k, v) => { setForm(f => ({ ...f, [k]: v })); if (server && server.field === k) setServer(null); };
            const setNic = (i, k, v) => setForm(f => ({ ...f, nics: f.nics.map((n, j) => (j === i ? { ...n, [k]: v } : n)) }));
            const errs = crBpCheck(form, t);
            const shown = tried ? errs : {};
            const err = (k) => shown[k] || (server && server.field === k ? server.msg : '');
            const odd = crBpOddKeys(form.sshkeys);
            const picked = cat.rows.find(r => r.id === form.template_id);
            const save = async () => {
                setTried(true);
                setServer(null);
                if (Object.keys(errs).length) return;
                setBusy(true);
                const res = await crBpSend(authFetch, bp ? `${API_URL}/blueprints/${encodeURIComponent(bp.id)}` : `${API_URL}/blueprints`,
                                           bp ? 'PUT' : 'POST', crBpBody(form));
                setBusy(false);
                if (res.ok && res.body && res.body.blueprint) { onSaved(res.body.blueprint, !bp); return; }
                const field = res.body && typeof res.body.field === 'string' ? res.body.field : '';
                setServer({ field, msg: crBpSendText(res, t) });
            };
            const general = server && (!server.field || !['name', 'description', 'template_id', 'cores', 'memory', 'disk_gb', 'cpu', 'nics',
                'ciuser', 'sshkeys', 'ip_mode', 'nameserver', 'searchdomain', 'tags'].includes(server.field));
            return (
                <CrUpdDialog id="bp-editor" wide sticky busy={busy} onCancel={onCancel}
                    title={bp ? crFill(t('crBpEditorEdit'), { name: bp.name }) : t('crBpEditorNew')}
                    footer={(
                        <>
                            <CrButton onClick={onCancel} disabled={busy} data-cr-bp-editor-cancel="">{t('cancel')}</CrButton>
                            <CrButton variant="primary" onClick={save} disabled={busy} data-cr-bp-editor-save="">{busy ? t('crNcSaving') : t('save')}</CrButton>
                        </>
                    )}>
                    <div className="cr-bp-editor" data-cr-bp-editor={bp ? bp.id : 'new'}>
                        {general && <CrUpdNote tone="error" id="bp-save">{server.msg}</CrUpdNote>}
                        <div className="cr-nc-form">
                            <CrBpField id="name" label={t('crBpFName')} error={err('name')}>
                                <input id="cr-nc-bp-name" className="cr-input" value={form.name} maxLength={100} onChange={e => set('name', e.target.value)} data-cr-bp-input="name" />
                            </CrBpField>
                            <CrBpField id="template_id" label={t('crBpFImage')} error={err('template_id')}
                                hint={cat.state === 'error' ? crFill(t('crBpCatalogFailed'), { reason: cat.why }) : t('crBpFImageHint')}>
                                <select id="cr-nc-bp-template_id" className="cr-select" value={form.template_id} onChange={e => set('template_id', e.target.value)}
                                    disabled={cat.state === 'loading'} data-cr-bp-input="template_id">
                                    <option value="">{cat.state === 'loading' ? t('crNcReading') : t('crBpFImagePick')}</option>
                                    {form.template_id && !picked && cat.state !== 'loading' && (
                                        <option value={form.template_id}>{(bp && bp.template_name) || form.template_id}</option>
                                    )}
                                    {cat.rows.map(r => <option key={r.id} value={r.id}>{r.name}{r.custom ? ` (${t('crBpCustom')})` : ''}</option>)}
                                </select>
                            </CrBpField>
                            <CrBpField id="description" label={t('crBpFDesc')} wide error={err('description')}>
                                <input id="cr-nc-bp-description" className="cr-input" value={form.description} maxLength={500} onChange={e => set('description', e.target.value)} data-cr-bp-input="description" />
                            </CrBpField>
                        </div>

                        <CrNcGroup id="bp-hw" title={t('crBpGroupHw')}>
                            <div className="cr-nc-form">
                                <CrBpField id="cores" label={t('crBpFCores')} error={err('cores')}>
                                    <input id="cr-nc-bp-cores" className="cr-input" inputMode="numeric" value={form.cores} onChange={e => set('cores', e.target.value)} data-cr-bp-input="cores" />
                                </CrBpField>
                                <CrBpField id="memory" label={t('crBpFMemory')} error={err('memory')}>
                                    <div className="cr-bp-unit">
                                        <input id="cr-nc-bp-memory" className="cr-input" inputMode="decimal" value={form.memory} onChange={e => set('memory', e.target.value)} data-cr-bp-input="memory" />
                                        <select className="cr-select" value={form.memUnit} onChange={e => set('memUnit', e.target.value)} aria-label={t('crBpMemUnit')} data-cr-bp-input="memUnit">
                                            <option value="GB">GB</option>
                                            <option value="MB">MB</option>
                                        </select>
                                    </div>
                                </CrBpField>
                                <CrBpField id="disk_gb" label={t('crBpFDisk')} error={err('disk_gb')} hint={t('crBpFDiskHint')}>
                                    <input id="cr-nc-bp-disk_gb" className="cr-input" inputMode="numeric" value={form.disk_gb} onChange={e => set('disk_gb', e.target.value)} data-cr-bp-input="disk_gb" />
                                </CrBpField>
                                <CrBpField id="cpu" label={t('crBpFCpu')} error={err('cpu')} hint={picked && picked.cpu ? crFill(t('crBpFCpuHintImage'), { cpu: picked.cpu }) : t('crBpFCpuHint')}>
                                    <input id="cr-nc-bp-cpu" className="cr-input cr-nc-mono-input" value={form.cpu} spellCheck={false} placeholder="x86-64-v2-AES" onChange={e => set('cpu', e.target.value)} data-cr-bp-input="cpu" />
                                </CrBpField>
                            </div>
                        </CrNcGroup>

                        <CrNcGroup id="bp-net" title={t('crBpGroupNet')}>
                            {err('nics') && <p className="cr-nc-hint cr-nc-hint-error" data-cr-nc-hint="error">{err('nics')}</p>}
                            {bridges.length > 0 && (
                                <datalist id="cr-bp-bridges">{bridges.map(b => <option key={b} value={b} />)}</datalist>
                            )}
                            <ul className="cr-bp-nics" aria-label={t('crBpGroupNet')}>
                                {form.nics.map((n, i) => (
                                    <li key={i} className="cr-bp-nic" data-cr-bp-nic={i}>
                                        <span className="cr-mono cr-bp-nic-id">{`net${i}`}</span>
                                        <CrBpField id={`nic${i}-bridge`} label={t('crBpFBridge')} error={err(`nic${i}-bridge`)}>
                                            <input id={`cr-nc-bp-nic${i}-bridge`} className="cr-input cr-nc-mono-input" value={n.bridge} spellCheck={false}
                                                list={bridges.length ? 'cr-bp-bridges' : undefined} onChange={e => setNic(i, 'bridge', e.target.value)} data-cr-bp-nic-bridge={i} />
                                        </CrBpField>
                                        <CrBpField id={`nic${i}-vlan`} label={t('crBpFVlan')} error={err(`nic${i}-vlan`)}>
                                            <input id={`cr-nc-bp-nic${i}-vlan`} className="cr-input" inputMode="numeric" value={n.vlan} placeholder={t('crBpVlanNone')}
                                                onChange={e => setNic(i, 'vlan', e.target.value)} data-cr-bp-nic-vlan={i} />
                                        </CrBpField>
                                        <CrBpField id={`nic${i}-model`} label={t('crBpFModel')}>
                                            <select id={`cr-nc-bp-nic${i}-model`} className="cr-select" value={n.model} onChange={e => setNic(i, 'model', e.target.value)} data-cr-bp-nic-model={i}>
                                                {CR_BP_MODELS.map(m => <option key={m} value={m}>{m}</option>)}
                                            </select>
                                        </CrBpField>
                                        <label className="cr-bp-check">
                                            <input type="checkbox" checked={n.firewall} onChange={e => setNic(i, 'firewall', e.target.checked)} data-cr-bp-nic-fw={i} />
                                            <span>{t('crBpFFirewall')}</span>
                                        </label>
                                        {form.nics.length > 1 && (
                                            <CrButton className="cr-btn-xs" icon={<Icons.X />} onClick={() => setForm(f => ({ ...f, nics: f.nics.filter((_, j) => j !== i) }))}
                                                title={crFill(t('crBpRemoveNic'), { n: `net${i}` })} aria-label={crFill(t('crBpRemoveNic'), { n: `net${i}` })} data-cr-bp-nic-remove={i} />
                                        )}
                                    </li>
                                ))}
                            </ul>
                            {form.nics.length < CR_BP_MAX_NICS && (
                                <div><CrButton className="cr-btn-xs" icon={<Icons.Plus />} onClick={() => setForm(f => ({ ...f, nics: [...f.nics, crBpNic()] }))} data-cr-bp-nic-add="">{t('crBpAddNic')}</CrButton></div>
                            )}
                        </CrNcGroup>

                        <CrNcGroup id="bp-ci" title={t('crBpGroupCi')}>
                            <div className="cr-nc-form">
                                <CrBpField id="ciuser" label={t('crBpFUser')} error={err('ciuser')}
                                    hint={picked && picked.default_user ? crFill(t('crBpFUserHintImage'), { user: picked.default_user }) : t('crBpFUserHint')}>
                                    <input id="cr-nc-bp-ciuser" className="cr-input" value={form.ciuser} spellCheck={false} autoComplete="off" onChange={e => set('ciuser', e.target.value)} data-cr-bp-input="ciuser" />
                                </CrBpField>
                                <CrBpField id="ip_mode" label={t('crBpFIpMode')} error={err('ip_mode')} hint={form.ip_mode === 'static' ? t('crBpIpStaticHint') : ''}>
                                    <select id="cr-nc-bp-ip_mode" className="cr-select" value={form.ip_mode} onChange={e => set('ip_mode', e.target.value)} data-cr-bp-input="ip_mode">
                                        {CR_BP_IP_MODES.map(m => <option key={m} value={m}>{t(CR_BP_IP_WORD[m])}</option>)}
                                    </select>
                                </CrBpField>
                                <CrBpField id="nameserver" label={t('crBpFDns')} error={err('nameserver')} hint={t('crBpFDnsHint')}>
                                    <input id="cr-nc-bp-nameserver" className="cr-input cr-nc-mono-input" value={form.nameserver} spellCheck={false} onChange={e => set('nameserver', e.target.value)} data-cr-bp-input="nameserver" />
                                </CrBpField>
                                <CrBpField id="searchdomain" label={t('crBpFSearch')} error={err('searchdomain')}>
                                    <input id="cr-nc-bp-searchdomain" className="cr-input" value={form.searchdomain} spellCheck={false} onChange={e => set('searchdomain', e.target.value)} data-cr-bp-input="searchdomain" />
                                </CrBpField>
                                <CrBpField id="sshkeys" label={t('crBpFKeys')} wide error={err('sshkeys')}
                                    hint={odd.length ? crFill(t('crBpKeysOdd'), { n: odd.join(', ') }) : t('crBpFKeysHint')}>
                                    <textarea id="cr-nc-bp-sshkeys" className="cr-input cr-nc-textarea cr-bp-keys" rows={3} value={form.sshkeys} spellCheck={false}
                                        placeholder="ssh-ed25519 AAAA... user@host" onChange={e => set('sshkeys', e.target.value)} data-cr-bp-input="sshkeys" />
                                </CrBpField>
                            </div>
                            <label className="cr-bp-check">
                                <input type="checkbox" checked={form.ciupgrade} onChange={e => set('ciupgrade', e.target.checked)} data-cr-bp-input="ciupgrade" />
                                <span>{t('crBpFUpgrade')}</span>
                            </label>
                            <p className="cr-bp-fine">{t('crBpNoPassword')}</p>
                        </CrNcGroup>

                        <CrNcGroup id="bp-more" title={t('crBpGroupMore')}>
                            <div className="cr-nc-form">
                                <CrBpField id="tags" label={t('crBpFTags')} error={err('tags')} hint={t('crBpFTagsHint')}>
                                    <input id="cr-nc-bp-tags" className="cr-input" value={form.tags} spellCheck={false} onChange={e => set('tags', e.target.value)} data-cr-bp-input="tags" />
                                </CrBpField>
                            </div>
                            <label className="cr-bp-check">
                                <input type="checkbox" checked={form.start} onChange={e => set('start', e.target.checked)} data-cr-bp-input="start" />
                                <span>{t('crBpFStart')}</span>
                            </label>
                        </CrNcGroup>
                    </div>
                </CrUpdDialog>
            );
        }

        // what the server says of a template of the blueprint's image on the picked node
        function CrBpTemplateHint({ tpl }) {
            const { t } = useTranslation();
            if (!tpl || tpl.state === 'idle') return null;
            if (tpl.state === 'loading') return <p className="cr-bp-fine" data-cr-bp-tpl="loading">{t('crBpTplReading')}</p>;
            if (tpl.state === 'error') return <CrUpdNote tone="warning" id="bp-tpl">{crFill(t('crBpTplFailed'), { reason: tpl.why })}</CrUpdNote>;
            const x = tpl.body && tpl.body.template;
            if (x && !tpl.body.build_needed) {
                return (
                    <CrUpdNote tone="info" id="bp-tpl">
                        <span data-cr-bp-tpl="existing" data-cr-bp-tpl-vmid={x.vmid}>
                            {crFill(t(x.shared ? 'crBpTplShared' : 'crBpTplUses'), { vmid: x.vmid, node: x.node, storage: x.storage || '' })}
                        </span>
                    </CrUpdNote>
                );
            }
            return <CrUpdNote tone="info" id="bp-tpl"><span data-cr-bp-tpl="build">{t('crBpTplBuild')}</span></CrUpdNote>;
        }

        // A deploy that runs: its row read every CR_BP_POLL while it is queued or running and this
        // view is open; the server goes on with it when the dialog is closed
        function CrBpProgress({ dep, onRow }) {
            const { t } = useTranslation();
            const [row, setRow] = useState(null);
            const [fail, setFail] = useState('');
            const onRowRef = useRef(onRow);
            onRowRef.current = onRow;
            useEffect(() => {
                let gone = false;
                let timer = null;
                const tick = async () => {
                    const read = await crBpReadRow(dep.authFetch, `${API_URL}/blueprints/deployments/${encodeURIComponent(dep.id)}`);
                    if (gone) return;
                    if (read.state === 'ok') {
                        setRow(read.body);
                        setFail('');
                        onRowRef.current(read.body);
                        if (!crBpLive(read.body.status)) return;
                    } else {
                        setFail(crDriftReadText(read, t));
                    }
                    timer = setTimeout(tick, CR_BP_POLL);
                };
                tick();
                return () => { gone = true; if (timer) clearTimeout(timer); };
            }, [dep.id]);
            const status = row ? row.status : 'queued';
            const step = row && CR_BP_STEPS.includes(row.step) ? row.step : (row && row.status === 'completed' ? 'done' : 'template');
            const at = CR_BP_STEPS.indexOf(step);
            const steps = CR_BP_STEPS.filter(s => s !== 'template' || dep.build_needed || step === 'template');
            const pct = row && Number.isFinite(Number(row.progress)) ? Math.max(0, Math.min(100, Number(row.progress))) : 0;
            const log = row && typeof row.log === 'string' ? row.log.split('\n').filter(Boolean).slice(-30) : [];
            return (
                <div className="cr-bp-progress" data-cr-bp-progress={dep.id} data-cr-bp-status={status}>
                    <div className="cr-bp-progline">
                        <CrBpState state={status} />
                        <span className="cr-mono">{crFill(t('crBpGuestLine'), { name: dep.name, vmid: dep.vmid })}</span>
                    </div>
                    <div className="cr-bp-bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} aria-label={t('crBpProgress')}>
                        <span className={`cr-bp-bar-fill cr-bp-bar-${status}`} style={{ width: `${pct}%` }} />
                    </div>
                    <ol className="cr-bp-steps" aria-label={t('crBpProgress')}>
                        {steps.map(s => {
                            const i = CR_BP_STEPS.indexOf(s);
                            const st = status === 'completed' || i < at ? 'done' : i === at ? (status === 'failed' ? 'failed' : 'current') : 'pending';
                            return <li key={s} className="cr-bp-step" data-cr-bp-step={s} data-state={st}>{t(CR_BP_STEP_WORD[s])}</li>;
                        })}
                    </ol>
                    {dep.build_needed && <p className="cr-bp-fine">{t('crBpProgBuild')}</p>}
                    {dep.quota_warning && <CrUpdNote tone="warning" id="bp-quota">{crFill(t('crBpQuotaWarn'), { msg: String(dep.quota_warning) })}</CrUpdNote>}
                    {fail && <CrUpdNote tone="warning" id="bp-prog-read">{crFill(t('crBpProgReadFailed'), { reason: fail })}</CrUpdNote>}
                    {row && row.status === 'failed' && <CrUpdNote tone="error" id="bp-failed"><span data-cr-bp-error="">{row.error || t('crBpStFailed')}</span></CrUpdNote>}
                    {log.length > 0 && (
                        <details className="cr-bp-logbox" open={status === 'failed'}>
                            <summary>{t('crBpLog')}</summary>
                            <pre className="cr-bp-log" data-cr-bp-log="">{log.join('\n')}</pre>
                        </details>
                    )}
                    {crBpLive(status) && <p className="cr-bp-fine">{t('crBpProgClosedNote')}</p>}
                </div>
            );
        }

        // The deploy dialog: where to, then the progress of the deploy it started
        function CrBpDeploy({ bp, clusters, clusterId, authFetch, canWrite, nav, onClose, onStarted }) {
            const { t } = useTranslation();
            const targets = (clusters || []).filter(c => c && (c.cluster_type ? c.cluster_type === 'proxmox' : true));
            const first = targets.find(c => c.id === clusterId) || targets[0] || null;
            const [form, setForm] = useState({ cluster_id: first ? first.id : '', node: '', storage: '', name: crBpVmName(bp.name), vmid: '',
                                               ip: '', gw: '', password: '', start: bp.start !== false });
            const [vmidTyped, setVmidTyped] = useState(false);
            const [nodes, setNodes] = useState({ state: 'idle', rows: [], why: '' });
            const [stores, setStores] = useState({ state: 'idle', rows: [], why: '' });
            const [tpl, setTpl] = useState({ state: 'idle' });
            const [tried, setTried] = useState(false);
            const [busy, setBusy] = useState(false);
            const [server, setServer] = useState('');
            const [dep, setDep] = useState(null);
            const [row, setRow] = useState(null);
            const seq = useRef({ c: 0, n: 0 });
            const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

            // a cluster picked: its online nodes and the next free VMID (the tenant's range, the create dialog's read)
            useEffect(() => {
                const cid = form.cluster_id;
                setNodes({ state: cid ? 'loading' : 'idle', rows: [], why: '' });
                setStores({ state: 'idle', rows: [], why: '' });
                setTpl({ state: 'idle' });
                setForm(f => ({ ...f, node: '', storage: '' }));
                if (!cid) return;
                const my = ++seq.current.c;
                crDriftRead(authFetch, `${API_URL}/clusters/${encodeURIComponent(cid)}/nodes`).then(read => {
                    if (my !== seq.current.c) return;
                    if (read.state !== 'ok') { setNodes({ state: 'error', rows: [], why: crDriftReadText(read, t) }); return; }
                    const list = Array.isArray(read.body) ? read.body : Array.isArray(read.body.data) ? read.body.data : [];
                    const rows = list.filter(n => n && (n.node || n.name) && (!n.status || n.status === 'online')).map(n => n.node || n.name).sort(crCompare);
                    setNodes({ state: 'ok', rows, why: '' });
                    if (rows.length) setForm(f => ({ ...f, node: rows[0] }));
                });
                if (!vmidTyped) {
                    crDriftRead(authFetch, `${API_URL}/clusters/${encodeURIComponent(cid)}/nextid`).then(read => {
                        if (my !== seq.current.c || read.state !== 'ok') return;
                        const v = Number(read.body.vmid);
                        if (Number.isInteger(v)) setForm(f => ({ ...f, vmid: String(v) }));
                    });
                }
            }, [form.cluster_id]);

            // a node picked: its storages for disk images, and whether a template of the image is there
            useEffect(() => {
                const { cluster_id: cid, node } = form;
                setStores({ state: node ? 'loading' : 'idle', rows: [], why: '' });
                setTpl({ state: node ? 'loading' : 'idle' });
                if (!cid || !node) return;
                const my = ++seq.current.n;
                const base = `${API_URL}/clusters/${encodeURIComponent(cid)}`;
                crDriftRead(authFetch, `${base}/nodes/${encodeURIComponent(node)}/storage`).then(read => {
                    if (my !== seq.current.n) return;
                    if (read.state !== 'ok') { setStores({ state: 'error', rows: [], why: crDriftReadText(read, t) }); return; }
                    const list = Array.isArray(read.body) ? read.body : Array.isArray(read.body.data) ? read.body.data : [];
                    const rows = [...new Set(list.filter(s => s && s.enabled !== 0 && s.active !== 0
                        && String(s.content || '').split(',').includes('images')).map(s => s.storage || s.name).filter(Boolean))];
                    setStores({ state: 'ok', rows, why: '' });
                    setForm(f => ({ ...f, storage: rows.includes(f.storage) ? f.storage : (rows[0] || '') }));
                });
                crDriftRead(authFetch, `${base}/blueprints/${encodeURIComponent(bp.id)}/template?node=${encodeURIComponent(node)}`).then(read => {
                    if (my !== seq.current.n) return;
                    if (read.state === 'ok') setTpl({ state: 'ok', body: read.body });
                    else setTpl({ state: 'error', why: crDriftReadText(read, t) });
                });
            }, [form.cluster_id, form.node]);

            const errs = {};
            if (!form.cluster_id) errs.cluster_id = t('crBpErrPick');
            if (!form.node) errs.node = t('crBpErrPick');
            if (!form.storage) errs.storage = t('crBpErrPick');
            if (!CR_BP_VMNAME_RE.test(form.name.trim())) errs.name = t('crBpErrVmName');
            if (form.vmid.trim() !== '' && !crBpIn(crBpInt(form.vmid), CR_BP_LIMITS.vmid)) errs.vmid = t('crBpErrVmid');
            if (bp.ip_mode === 'static') {
                if (!crBpIsCidr(form.ip)) errs.ip = t('crBpErrIp');
                if (form.gw.trim() !== '' && !crBpIsIp(form.gw)) errs.gw = t('crBpErrGw');
            }
            const err = (k) => (tried ? errs[k] || '' : '');

            const go = async () => {
                setTried(true);
                setServer('');
                if (Object.keys(errs).length) return;
                const body = { cluster_id: form.cluster_id, node: form.node, storage: form.storage, name: form.name.trim(), start: !!form.start };
                if (form.vmid.trim() !== '') body.vmid = crBpInt(form.vmid);
                if (bp.ip_mode === 'static') body.ipconfig0 = crBpIpconfig(form.ip, form.gw);
                if (form.password) body.cipassword = form.password;
                setBusy(true);
                const res = await crBpSend(authFetch, `${API_URL}/blueprints/${encodeURIComponent(bp.id)}/deploy`, 'POST', body);
                setBusy(false);
                if (res.ok && res.body && res.body.deployment_id) {
                    setDep({ id: res.body.deployment_id, vmid: res.body.vmid, name: res.body.name || body.name, cid: form.cluster_id,
                             node: form.node, build_needed: !!res.body.build_needed, quota_warning: res.body.quota_warning || '', authFetch });
                    setForm(f => ({ ...f, password: '' }));
                    onStarted();
                    return;
                }
                setServer(crBpSendText(res, t));
            };

            const cl = targets.find(c => c.id === form.cluster_id);
            const done = row && row.status === 'completed';
            const openGuest = () => {
                const node = (row && row.node) || dep.node;
                onClose();
                nav.openGuest(dep.cid, { vmid: Number(dep.vmid), node, type: 'qemu', name: dep.name, status: form.start ? 'running' : 'stopped' });
            };
            const footer = dep ? (
                <>
                    {done && nav && typeof nav.openGuest === 'function' && (
                        <CrButton variant="primary" onClick={openGuest} data-cr-bp-open-guest={dep.vmid}>{crFill(t('crBpOpenGuest'), { vmid: dep.vmid })}</CrButton>
                    )}
                    <CrButton onClick={onClose} data-cr-bp-deploy-close="">{t('close')}</CrButton>
                </>
            ) : (
                <>
                    <CrButton onClick={onClose} disabled={busy} data-cr-bp-deploy-cancel="">{t('cancel')}</CrButton>
                    <CrButton variant="primary" onClick={go} disabled={busy || !canWrite || !targets.length} data-cr-bp-deploy-go="">{busy ? t('crBpStarting') : t('crBpDeployGo')}</CrButton>
                </>
            );
            return (
                <CrUpdDialog id="bp-deploy" sticky busy={busy} onCancel={onClose} footer={footer}
                    title={crFill(t(dep ? 'crBpProgTitle' : 'crBpDeployTitle'), { name: bp.name })}
                    sub={dep && cl ? `${cl.display_name || cl.name} · ${dep.node}` : undefined}>
                    {dep ? <CrBpProgress dep={dep} onRow={setRow} /> : (
                        <div className="cr-bp-deploy" data-cr-bp-deploy-form={bp.id}>
                            {server && <CrUpdNote tone="error" id="bp-deploy">{server}</CrUpdNote>}
                            {!targets.length ? <CrUpdNote tone="warning" id="bp-noclusters">{t('crBpNoClusters')}</CrUpdNote> : (
                                <div className="cr-nc-form">
                                    <CrBpField id="cluster_id" label={t('crBpFCluster')} error={err('cluster_id')}>
                                        <select id="cr-nc-bp-cluster_id" className="cr-select" value={form.cluster_id} onChange={e => set('cluster_id', e.target.value)} data-cr-bp-dep="cluster_id">
                                            {targets.map(c => <option key={c.id} value={c.id}>{c.display_name || c.name}</option>)}
                                        </select>
                                    </CrBpField>
                                    <CrBpField id="node" label={t('crBpFNode')} error={err('node')}
                                        hint={nodes.state === 'error' ? crFill(t('crBpNodesFailed'), { reason: nodes.why }) : nodes.state === 'ok' && !nodes.rows.length ? t('crBpNoNodes') : ''}>
                                        <select id="cr-nc-bp-node" className="cr-select" value={form.node} onChange={e => set('node', e.target.value)}
                                            disabled={nodes.state !== 'ok' || !nodes.rows.length} data-cr-bp-dep="node">
                                            {nodes.state === 'loading' && <option value="">{t('crNcReading')}</option>}
                                            {nodes.rows.map(n => <option key={n} value={n}>{n}</option>)}
                                        </select>
                                    </CrBpField>
                                    <CrBpField id="storage" label={t('crBpFStorage')} error={err('storage')}
                                        hint={stores.state === 'error' ? crFill(t('crBpStoragesFailed'), { reason: stores.why }) : stores.state === 'ok' && !stores.rows.length ? t('crBpNoStorages') : ''}>
                                        <select id="cr-nc-bp-storage" className="cr-select" value={form.storage} onChange={e => set('storage', e.target.value)}
                                            disabled={stores.state !== 'ok' || !stores.rows.length} data-cr-bp-dep="storage">
                                            {stores.state === 'loading' && <option value="">{t('crNcReading')}</option>}
                                            {stores.rows.map(s => <option key={s} value={s}>{s}</option>)}
                                        </select>
                                    </CrBpField>
                                    <CrBpField id="vmname" label={t('crBpFVmName')} error={err('name')}>
                                        <input id="cr-nc-bp-vmname" className="cr-input" value={form.name} spellCheck={false} maxLength={63} onChange={e => set('name', e.target.value)} data-cr-bp-dep="name" />
                                    </CrBpField>
                                    <CrBpField id="vmid" label={t('crBpFVmid')} error={err('vmid')} hint={t('crBpFVmidHint')}>
                                        <input id="cr-nc-bp-vmid" className="cr-input" inputMode="numeric" value={form.vmid}
                                            onChange={e => { setVmidTyped(true); set('vmid', e.target.value); }} data-cr-bp-dep="vmid" />
                                    </CrBpField>
                                    {bp.ip_mode === 'static' && (
                                        <>
                                            <CrBpField id="ip" label={t('crBpFIp')} error={err('ip')}>
                                                <input id="cr-nc-bp-ip" className="cr-input cr-nc-mono-input" value={form.ip} spellCheck={false} placeholder="10.0.0.5/24" onChange={e => set('ip', e.target.value)} data-cr-bp-dep="ip" />
                                            </CrBpField>
                                            <CrBpField id="gw" label={t('crBpFGw')} error={err('gw')}>
                                                <input id="cr-nc-bp-gw" className="cr-input cr-nc-mono-input" value={form.gw} spellCheck={false} placeholder="10.0.0.1" onChange={e => set('gw', e.target.value)} data-cr-bp-dep="gw" />
                                            </CrBpField>
                                        </>
                                    )}
                                    <CrBpField id="password" label={t('crBpFPassword')} hint={t('crBpFPasswordHint')}>
                                        <input id="cr-nc-bp-password" type="password" className="cr-input" value={form.password} autoComplete="new-password" onChange={e => set('password', e.target.value)} data-cr-bp-dep="password" />
                                    </CrBpField>
                                </div>
                            )}
                            {targets.length > 0 && (
                                <label className="cr-bp-check">
                                    <input type="checkbox" checked={form.start} onChange={e => set('start', e.target.checked)} data-cr-bp-dep="start" />
                                    <span>{t('crBpFStartNow')}</span>
                                </label>
                            )}
                            <CrBpTemplateHint tpl={tpl} />
                            <p className="cr-bp-fine">{crFill(t('crBpDeploySummary'), { hw: crBpHw(bp, t), ip: t(CR_BP_IP_WORD[bp.ip_mode] || 'crBpIpDhcp') })}</p>
                        </div>
                    )}
                </CrUpdDialog>
            );
        }

        // --- the page ------------------------------------------------------------------------------

        // canRead: the account holds vm.create (the routes ask for it); canWrite: it may use it here
        // (not on a standby). nav: the task center's navigation, for the guest a deploy made
        function CrBlueprints({ cluster, clusters, authFetch, addToast, canRead, canWrite, nav }) {
            const { t } = useTranslation();
            const { haReadOnly } = useAuth();
            const cid = cluster && cluster.id;
            const [list, setList] = useState({ state: 'loading', rows: [], why: '' });
            const [recent, setRecent] = useState({ state: 'loading', rows: [], why: '' });
            const [editor, setEditor] = useState(null);
            const [deploy, setDeploy] = useState(null);
            const [del, setDel] = useState(null);
            const [delBusy, setDelBusy] = useState(false);
            const [bridges, setBridges] = useState([]);
            const write = canWrite && !haReadOnly;

            const loadList = async () => {
                if (!canRead) return;
                setList(l => ({ ...l, state: l.state === 'ok' ? 'ok' : 'loading' }));
                const read = await crDriftRead(authFetch, `${API_URL}/blueprints`);
                if (read.state === 'ok') setList({ state: 'ok', rows: Array.isArray(read.body.blueprints) ? read.body.blueprints : [], why: '' });
                else setList({ state: 'error', rows: [], why: crDriftReadText(read, t) });
            };
            const loadRecent = async () => {
                if (!cid || !canRead) return;
                const read = await crDriftRead(authFetch, `${API_URL}/blueprints/deployments?cluster_id=${encodeURIComponent(cid)}`);
                if (read.state === 'ok') setRecent({ state: 'ok', rows: Array.isArray(read.body.deployments) ? read.body.deployments : [], why: '' });
                else setRecent({ state: 'error', rows: [], why: crDriftReadText(read, t) });
            };
            useEffect(() => { loadList(); }, [canRead]);
            useEffect(() => { loadRecent(); }, [cid, canRead]);

            // the bridges of one online node of this cluster, once, for the NIC fields of the editor
            const openEditor = (bp) => {
                setEditor({ bp });
                if (bridges.length || !cid) return;
                const metrics = nav && typeof nav.nodesOf === 'function' ? nav.nodesOf(cid) : null;
                const node = metrics ? Object.keys(metrics).sort(crCompare).find(n => !metrics[n] || metrics[n].status !== 'offline') : null;
                if (!node) return;
                crDriftRead(authFetch, `${API_URL}/clusters/${encodeURIComponent(cid)}/nodes/${encodeURIComponent(node)}/network`).then(read => {
                    if (read.state !== 'ok') return;
                    const rows = Array.isArray(read.body) ? read.body : Array.isArray(read.body.data) ? read.body.data : [];
                    setBridges([...new Set(rows.filter(r => r && /bridge/i.test(String(r.type || ''))).map(r => r.iface).filter(Boolean))].sort(crCompare));
                });
            };

            const saved = (bp, isNew) => {
                setEditor(null);
                addToast(t(isNew ? 'crBpCreated' : 'crBpSaved'), 'success');
                loadList();
            };
            const remove = async () => {
                if (!del) return;
                setDelBusy(true);
                const res = await crBpSend(authFetch, `${API_URL}/blueprints/${encodeURIComponent(del.id)}`, 'DELETE');
                setDelBusy(false);
                if (res.ok) { setDel(null); addToast(t('crBpDeleted'), 'success'); loadList(); return; }
                addToast(crBpSendText(res, t), 'error');
            };

            const why = !write ? t(haReadOnly ? 'crBpStandby' : 'crBpNeedsPerm') : undefined;
            const cols = [
                { key: 'name', label: t('crBpColName'), flex: true, min: 160, sortValue: r => r.name || '', render: r => (
                    <span className="cr-bp-name" data-cr-bp-row={r.id} title={r.description || undefined}>
                        <span className="cr-strong">{r.name}</span>
                        {r.description && <span className="cr-bp-desc">{r.description}</span>}
                    </span>) },
                { key: 'image', label: t('crBpColImage'), flex: true, min: 150, sortValue: r => r.template_name || '', render: r => (r.template_missing
                    ? <span data-cr-bp-image="missing" title={t('crBpImageGoneHint')}><CrBadge tone="warning">{t('crBpImageGone')}</CrBadge></span>
                    : <span data-cr-bp-image={r.template_id}>{r.template_name || r.template_id}</span>) },
                { key: 'hw', label: t('crBpColHw'), width: 190, sortable: false, render: r => <span className="cr-bp-hw">{crBpHw(r, t)}</span> },
                { key: 'nics', label: t('crBpColNics'), width: 72, align: 'right', sortValue: r => (Array.isArray(r.nics) ? r.nics.length : 0),
                  render: r => String(Array.isArray(r.nics) ? r.nics.length : 0) },
                { key: 'ip', label: t('crBpColIp'), width: 90, sortValue: r => r.ip_mode || '', render: r => t(CR_BP_IP_WORD[r.ip_mode] || 'crBpIpDhcp') },
                { key: 'by', label: t('crBpColBy'), width: 110, sortValue: r => r.created_by || '', render: r => r.created_by || '' },
                { key: 'act', label: '', width: 220, sortable: false, render: r => (
                    <span className="cr-bp-acts">
                        <CrButton className="cr-btn-xs" variant="primary" icon={<Icons.Play />} disabled={!write || r.template_missing}
                            title={r.template_missing ? t('crBpImageGoneHint') : why} onClick={e => { e.stopPropagation(); setDeploy(r); }} data-cr-bp-deploy={r.id}>{t('crBpDeploy')}</CrButton>
                        {r.can_edit && (
                            <>
                                <CrButton className="cr-btn-xs" icon={<Icons.Edit />} disabled={!write} title={why}
                                    onClick={e => { e.stopPropagation(); openEditor(r); }} data-cr-bp-edit={r.id}>{t('edit')}</CrButton>
                                <CrButton className="cr-btn-xs" icon={<Icons.Trash2 />} disabled={!write} title={why}
                                    onClick={e => { e.stopPropagation(); setDel(r); }} data-cr-bp-delete={r.id} aria-label={crFill(t('crBpDeleteTitle'), { name: r.name })} />
                            </>
                        )}
                    </span>) },
            ];
            const recentCols = [
                { key: 'bp', label: t('crBpColBlueprint'), flex: true, min: 140, render: r => r.blueprint_name || r.blueprint_id || '' },
                { key: 'guest', label: t('crBpColGuest'), flex: true, min: 140, sortValue: r => Number(r.vmid) || 0, render: r => {
                    const label = r.name ? `${r.name} (${r.vmid})` : String(r.vmid || '');
                    return r.status === 'completed' && nav && typeof nav.openGuest === 'function' && r.vmid
                        ? <button type="button" className="cr-link" data-cr-bp-guest={r.vmid}
                            onClick={e => { e.stopPropagation(); nav.openGuest(cid, { vmid: Number(r.vmid), node: r.node, type: 'qemu', name: r.name || '' }); }}>{label}</button>
                        : <span className="cr-mono">{label}</span>;
                } },
                { key: 'node', label: t('crBpColNode'), width: 100, render: r => r.node || '' },
                { key: 'state', label: t('crBpColState'), width: 110, sortValue: r => r.status || '', render: r => (
                    <span title={r.status === 'failed' && r.error ? r.error : undefined}><CrBpState state={r.status} /></span>) },
                { key: 'at', label: t('crBpColStarted'), width: 140, sortValue: r => r.started_at || '',
                  render: r => (r.started_at ? <span title={t('crDriftServerTime')}>{crDriftTime(String(r.started_at))}</span> : '') },
                { key: 'by', label: t('crBpColBy'), width: 110, render: r => r.started_by || '' },
            ];

            if (!canRead) {
                return (
                    <CrNcSection id="bp" className="cr-bp" data-cr-bp="" title={t('crBpTitle')} desc={t('crBpDesc')}>
                        <CrNcState id="bp" kind="info" data-cr-bp-noperm="">{t('crBpNoPerm')}</CrNcState>
                    </CrNcSection>
                );
            }
            return (
                <div className="cr-bp" data-cr-bp="">
                    <CrNcSection id="bp" title={t('crBpTitle')} desc={t('crBpDesc')}
                        badge={list.state === 'ok' ? <CrBadge tone="neutral" dot={false}>{list.rows.length}</CrBadge> : null}
                        actions={<CrButton variant="primary" icon={<Icons.Plus />} disabled={!write} title={why} onClick={() => openEditor(null)} data-cr-bp-new="">{t('crBpNew')}</CrButton>}>
                        {haReadOnly && <CrNcState id="bp-standby" kind="info">{t('crBpStandby')}</CrNcState>}
                        {list.state === 'loading' ? <CrNcState id="bp" kind="loading" />
                            : list.state === 'error' ? <CrNcState id="bp" kind="error" onRetry={loadList} data-cr-bp-error="">{crFill(t('crBpReadFailed'), { reason: list.why })}</CrNcState>
                            : !list.rows.length ? <p className="cr-bp-fine" data-cr-bp-empty="">{t('crBpEmpty')}</p>
                            : <CrTable id="bp-list" columns={cols} rows={list.rows} rowKey={r => r.id} ariaLabel={t('crBpTitle')} rowHeight={40}
                                initialSort={{ key: 'name', dir: 'asc' }} showCount={false} />}
                    </CrNcSection>
                    <CrNcSection id="bp-recent" title={t('crBpRecentTitle')} desc={t('crBpRecentDesc')}
                        actions={<CrButton className="cr-btn-xs" icon={<Icons.RefreshCw />} onClick={loadRecent} data-cr-bp-recent-refresh="">{t('refresh')}</CrButton>}>
                        {recent.state === 'loading' ? <CrNcState id="bp-recent" kind="loading" />
                            : recent.state === 'error' ? <CrNcState id="bp-recent" kind="error" onRetry={loadRecent}>{crFill(t('crBpRecentFailed'), { reason: recent.why })}</CrNcState>
                            : !recent.rows.length ? <p className="cr-bp-fine" data-cr-bp-recent-empty="">{t('crBpRecentNone')}</p>
                            : <CrTable id="bp-recent" columns={recentCols} rows={recent.rows} rowKey={r => r.id} ariaLabel={t('crBpRecentTitle')}
                                rowHeight={30} columnMenu={false} showCount={false} />}
                    </CrNcSection>
                    {editor && <CrBpEditor bp={editor.bp} authFetch={authFetch} bridges={bridges} onCancel={() => setEditor(null)} onSaved={saved} />}
                    {deploy && (
                        <CrBpDeploy bp={deploy} clusters={clusters} clusterId={cid} authFetch={authFetch} canWrite={write} nav={nav}
                            onClose={() => { setDeploy(null); loadRecent(); }} onStarted={loadRecent} />
                    )}
                    {del && (
                        <CrNcConfirm id="bp-delete" title={crFill(t('crBpDeleteTitle'), { name: del.name })} goLabel={t('delete')} busy={delBusy}
                            onCancel={() => setDel(null)} onConfirm={remove}>
                            <p>{t('crBpDeleteText')}</p>
                        </CrNcConfirm>
                    )}
                </div>
            );
        }
