        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned: the Blueprints & Images sub tab - LW Nov 2026 (#1220)
        // The blueprints on top (cr_blueprints.js), the images of the template library under them
        // with what this cluster has of each, and one list of what was deployed and built. A
        // blueprint names an image, and its first deploy onto a node without a template of it
        // builds one there: building one by hand is for the administrators who want it ready.
        // The page reads the library, the templates of this cluster and its recent deploys once,
        // again on Refresh and every CR_IMG_POLL while a build or a deploy of it runs. All
        // clusters is read when it is picked.
        // ═══════════════════════════════════════════════════════════

        const CR_IMG_POLL = 4000;
        const CR_IMG_RECENT_MAX = 100;
        // how many clusters the All clusters list asks at the same time
        const CR_IMG_PARALLEL = 6;
        // the width of the page: from CR_IMG_WIDE every row action keeps its label, under it Build
        // template here is an icon; under CR_IMG_NARROW (a tablet, a phone) Spec, Tags and Used by
        // go to the column menu so the actions stay in view
        const CR_IMG_WIDE = 1060;
        const CR_IMG_NARROW = 880;
        const CR_IMG_VMID = [100, 999999999];
        // a template name as the library route takes it
        const CR_IMG_NAME_RE = /^[A-Za-z0-9._-]+$/;
        const CR_IMG_STATE_TONE = { queued: 'neutral', running: 'info', completed: 'success', failed: 'error' };
        const CR_IMG_STATE_WORD = { queued: 'crImgStQueued', running: 'crImgStRunning', completed: 'crImgStCompleted', failed: 'crImgStFailed' };
        const crImgLive = (r) => !!r && (r.status === 'queued' || r.status === 'running');
        const crImgPve = (c) => !!c && (c.cluster_type ? c.cluster_type === 'proxmox' : true);
        const crImgInt = (v) => (/^\s*\d+\s*$/.test(String(v == null ? '' : v)) ? parseInt(v, 10) : NaN);
        const crImgName = (c) => (c ? c.display_name || c.name || c.id : '');

        // one request for the sections that ask for the same list at the same moment (the blueprints
        // and the images both read /blueprints when the page opens). Each caller gets its own copy of
        // the answer; anything but a plain GET goes straight through
        function crImgShared(authFetch) {
            const flying = new Map();
            return (url, opts) => {
                if (opts !== undefined || typeof url !== 'string') return authFetch(url, opts);
                if (!flying.has(url)) flying.set(url, Promise.resolve(authFetch(url)).finally(() => flying.delete(url)));
                return flying.get(url).then(r => (r && typeof r.clone === 'function' ? r.clone() : r));
            };
        }

        async function crImgSend(authFetch, url, method, body) {
            const r = await authFetch(url, { method, headers: { 'Content-Type': 'application/json' },
                                             body: body === undefined ? undefined : JSON.stringify(body) });
            if (!r) return { ok: false, code: 0, body: null };
            if (await haLeaderAway(r)) return { ok: false, code: 503, away: true, body: null };
            const data = await r.json().catch(() => null);
            return { ok: r.ok && !(data && data.error), code: r.status, body: data };
        }
        const crImgSendText = (res, t) => (res.away ? t('crDriftOffline')
            : [res.body && typeof res.body.error === 'string' ? res.body.error : '', res.code ? `HTTP ${res.code}` : ''].filter(Boolean).join(' - ')
              || t('crLoadFailed'));

        // a list read as {state, rows, why}; key is where the answer keeps the rows
        function crImgList(read, key, t) {
            if (read.state !== 'ok') return { state: 'error', rows: [], why: crDriftReadText(read, t) };
            return { state: 'ok', rows: Array.isArray(read.body[key]) ? read.body[key] : [], why: '' };
        }

        function crImgSpec(img) {
            const mem = Number(img.memory) || 0;
            const ram = mem >= 1024 && mem % 1024 === 0 ? `${mem / 1024} GB` : `${mem} MB`;
            return `${img.cores} vCPU · ${ram} · ${img.disk_gb} GB`;
        }

        // what this cluster has of an image: the templates the library built from it that are still
        // there (the VMID of a finished build, as a blueprint deploy finds them), the builds on their
        // way, and the last build when it failed and nothing else is there
        function crImgHere(img, builds, existing) {
            const mine = builds.filter(d => d && d.template_id === img.id);
            const live = new Map(existing.map(e => [Number(e.vmid), e]));
            const seen = new Set();
            const tpls = [];
            mine.forEach(d => {
                const vmid = Number(d.vmid);
                if (d.status !== 'completed' || !live.has(vmid) || seen.has(vmid)) return;
                seen.add(vmid);
                tpls.push({ vmid, node: live.get(vmid).node || d.node || '' });
            });
            const building = mine.filter(crImgLive);
            const failed = !tpls.length && !building.length && mine[0] && mine[0].status === 'failed' ? mine[0] : null;
            return { tpls, building, failed };
        }
        const crImgHereRank = (h) => (h.tpls.length ? 3 : h.building.length ? 2 : h.failed ? 1 : 0);

        // the blueprint deploys and the template builds as one list, newest first. A build a
        // blueprint deploy started first says which one
        function crImgMerge(deploys, builds) {
            const forBp = new Map(deploys.filter(d => d && d.build_dep_id).map(d => [d.build_dep_id, d.blueprint_name || '']));
            const pick = (r, cid) => ({ cid: r.cluster_id || cid || '', node: r.node || '', vmid: r.vmid, status: r.status || 'queued',
                                        progress: r.progress, error: r.error || '', started_at: r.started_at || '', started_by: r.started_by || '' });
            const out = deploys.filter(Boolean).map(d => ({ key: `bp:${d.id}`, kind: 'vm', what: d.blueprint_name || d.blueprint_id || '',
                                                            name: d.name || '', forBp: '', ...pick(d) }))
                .concat(builds.filter(Boolean).map(b => ({ key: `tpl:${b.id}`, kind: 'tpl', what: b.template_name || b.template_id || '',
                                                           name: '', forBp: forBp.get(b.id) || '', ...pick(b) })));
            return out.sort((a, b) => String(b.started_at).localeCompare(String(a.started_at)));
        }

        // --- the parts -----------------------------------------------------------------------------

        function CrImgField({ id, label, hint, error, wide, children }) {
            return (
                <CrNcField id={`img-${id}`} label={label} wide={wide} hint={error || hint} hintTone={error ? 'error' : undefined}>
                    {children}
                </CrNcField>
            );
        }

        function CrImgState({ row }) {
            const { t } = useTranslation();
            const pct = Number(row.progress);
            return (
                <span className="cr-img-state" data-cr-img-state={row.status}>
                    <CrBadge tone={CR_IMG_STATE_TONE[row.status] || 'neutral'}>{t(CR_IMG_STATE_WORD[row.status] || 'crImgStQueued')}</CrBadge>
                    {row.status === 'running' && Number.isFinite(pct) && <span className="cr-img-pct">{`${Math.max(0, Math.min(100, Math.round(pct)))}%`}</span>}
                    {row.status === 'failed' && row.error && <span className="cr-img-err" title={row.error}>{row.error}</span>}
                </span>
            );
        }

        // the On this cluster cell of an image
        function CrImgHere({ here, unread, pve }) {
            const { t } = useTranslation();
            if (!pve) return <span className="cr-muted" data-cr-img-here="na" title={t('crImgNotPve')}>{t('crImgHereNa')}</span>;
            if (unread) return <span className="cr-muted" data-cr-img-here="unread" title={unread}>{t('crImgHereUnread')}</span>;
            const { tpls, building, failed } = here;
            const runs = building.map(b => crFill(t('crImgHereBuilding'), { node: b.node || '', pct: Math.max(0, Math.min(100, Math.round(Number(b.progress) || 0))) }));
            if (!tpls.length && !runs.length) {
                if (failed) {
                    return <span data-cr-img-here="failed" title={failed.error || undefined}><CrBadge tone="warning">{t('crImgHereFailed')}</CrBadge></span>;
                }
                return <span className="cr-muted" data-cr-img-here="none" title={t('crImgHereNoneHint')}>{t('crImgHereNone')}</span>;
            }
            const all = tpls.map(x => crFill(t('crImgHerePresent'), { vmid: x.vmid, node: x.node }));
            return (
                <span className="cr-img-here" data-cr-img-here={tpls.length ? 'present' : 'building'} title={all.concat(runs).join('\n')}>
                    {tpls.length > 0 && <CrBadge tone="success">{all[0]}</CrBadge>}
                    {tpls.length > 1 && <span className="cr-muted">{crFill(t('crImgHereMore'), { n: tpls.length - 1 })}</span>}
                    {runs.length > 0 && <span className="cr-img-building" data-cr-img-building="">{runs[0]}</span>}
                </span>
            );
        }

        // Build template here: the library's own deploy of an image onto a node of this cluster
        function CrImgBuild({ img, cluster, authFetch, onCancel, onStarted }) {
            const { t } = useTranslation();
            const base = `${API_URL}/clusters/${encodeURIComponent(cluster.id)}`;
            const [form, setForm] = useState({ node: '', storage: '', vmid: '', name: '' });
            const [nodes, setNodes] = useState({ state: 'loading', rows: [], why: '' });
            const [stores, setStores] = useState({ state: 'idle', rows: [], why: '' });
            const [tried, setTried] = useState(false);
            const [busy, setBusy] = useState(false);
            const [server, setServer] = useState('');
            const seq = useRef(0);
            const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

            useEffect(() => {
                crDriftRead(authFetch, `${base}/nodes`).then(read => {
                    if (read.state !== 'ok') { setNodes({ state: 'error', rows: [], why: crDriftReadText(read, t) }); return; }
                    const list = Array.isArray(read.body) ? read.body : Array.isArray(read.body.data) ? read.body.data : [];
                    const rows = list.filter(n => n && (n.node || n.name) && (!n.status || n.status === 'online')).map(n => n.node || n.name).sort(crCompare);
                    setNodes({ state: 'ok', rows, why: '' });
                    if (rows.length) set('node', rows[0]);
                });
            }, []);
            // the storages of the picked node that take disk images
            useEffect(() => {
                const node = form.node;
                setStores({ state: node ? 'loading' : 'idle', rows: [], why: '' });
                if (!node) return;
                const my = ++seq.current;
                crDriftRead(authFetch, `${base}/nodes/${encodeURIComponent(node)}/storage`).then(read => {
                    if (my !== seq.current) return;
                    if (read.state !== 'ok') { setStores({ state: 'error', rows: [], why: crDriftReadText(read, t) }); return; }
                    const list = Array.isArray(read.body) ? read.body : Array.isArray(read.body.data) ? read.body.data : [];
                    const rows = [...new Set(list.filter(s => s && s.enabled !== 0 && s.active !== 0
                        && String(s.content || '').split(',').includes('images')).map(s => s.storage || s.name).filter(Boolean))];
                    setStores({ state: 'ok', rows, why: '' });
                    setForm(f => ({ ...f, storage: rows.includes(f.storage) ? f.storage : (rows[0] || '') }));
                });
            }, [form.node]);

            const errs = {};
            if (!form.node) errs.node = t('crImgErrPick');
            if (!form.storage) errs.storage = t('crImgErrPick');
            const vmid = crImgInt(form.vmid);
            if (form.vmid.trim() !== '' && !(vmid >= CR_IMG_VMID[0] && vmid <= CR_IMG_VMID[1])) errs.vmid = t('crImgErrVmid');
            if (form.name.trim() !== '' && !CR_IMG_NAME_RE.test(form.name.trim())) errs.name = t('crImgErrName');
            const err = (k) => (tried ? errs[k] || '' : '');
            // the name the server gives a template when none is typed
            const auto = `tpl-${img.distro || ''}-${img.version || ''}`.replace(/\./g, '');

            const go = async () => {
                setTried(true);
                setServer('');
                if (Object.keys(errs).length) return;
                const body = { template_id: img.id, node: form.node, storage: form.storage };
                if (form.vmid.trim() !== '') body.vmid = vmid;
                if (form.name.trim() !== '') body.name = form.name.trim();
                setBusy(true);
                const res = await crImgSend(authFetch, `${base}/templates/deploy`, 'POST', body);
                setBusy(false);
                if (res.ok && res.body && res.body.deployment_id) { onStarted(res.body); return; }
                setServer(crImgSendText(res, t));
            };
            return (
                <CrUpdDialog id="img-build" sticky busy={busy} onCancel={onCancel}
                    title={crFill(t('crImgBuildTitle'), { name: img.name })} sub={crImgName(cluster)}
                    footer={(
                        <>
                            <CrButton onClick={onCancel} disabled={busy} data-cr-img-build-cancel="">{t('cancel')}</CrButton>
                            <CrButton variant="primary" onClick={go} disabled={busy} data-cr-img-build-go="">{busy ? t('crImgStarting') : t('crImgBuildGo')}</CrButton>
                        </>
                    )}>
                    <div className="cr-img-dialog" data-cr-img-build-form={img.id}>
                        {server && <CrUpdNote tone="error" id="img-build">{server}</CrUpdNote>}
                        <div className="cr-nc-form">
                            <CrImgField id="node" label={t('crImgFNode')} error={err('node')}
                                hint={nodes.state === 'error' ? crFill(t('crImgNodesFailed'), { reason: nodes.why }) : nodes.state === 'ok' && !nodes.rows.length ? t('crImgNoNodes') : ''}>
                                <select id="cr-nc-img-node" className="cr-select" value={form.node} onChange={e => set('node', e.target.value)}
                                    disabled={nodes.state !== 'ok' || !nodes.rows.length} data-cr-img-b="node">
                                    {nodes.state === 'loading' && <option value="">{t('crNcReading')}</option>}
                                    {nodes.rows.map(n => <option key={n} value={n}>{n}</option>)}
                                </select>
                            </CrImgField>
                            <CrImgField id="storage" label={t('crImgFStorage')} error={err('storage')}
                                hint={stores.state === 'error' ? crFill(t('crImgStoragesFailed'), { reason: stores.why }) : stores.state === 'ok' && !stores.rows.length ? t('crImgNoStorages') : ''}>
                                <select id="cr-nc-img-storage" className="cr-select" value={form.storage} onChange={e => set('storage', e.target.value)}
                                    disabled={stores.state !== 'ok' || !stores.rows.length} data-cr-img-b="storage">
                                    {stores.state === 'loading' && <option value="">{t('crNcReading')}</option>}
                                    {stores.rows.map(s => <option key={s} value={s}>{s}</option>)}
                                </select>
                            </CrImgField>
                            <CrImgField id="vmid" label={t('crImgFVmid')} error={err('vmid')} hint={t('crImgFVmidHint')}>
                                <input id="cr-nc-img-vmid" className="cr-input" inputMode="numeric" value={form.vmid} onChange={e => set('vmid', e.target.value)} data-cr-img-b="vmid" />
                            </CrImgField>
                            <CrImgField id="name" label={t('crImgFTplName')} error={err('name')} hint={crFill(t('crImgFTplNameHint'), { name: auto })}>
                                <input id="cr-nc-img-name" className="cr-input cr-nc-mono-input" value={form.name} spellCheck={false} maxLength={63}
                                    placeholder={auto} onChange={e => set('name', e.target.value)} data-cr-img-b="name" />
                            </CrImgField>
                        </div>
                        <CrUpdNote tone="info" id="img-build-hint">{t('crImgBuildHint')}</CrUpdNote>
                    </div>
                </CrUpdDialog>
            );
        }

        const CR_IMG_ADD_EMPTY = { name: '', image_url: '', description: '', distro: '', version: '', default_user: 'root',
                                   cores: '2', memory: '2048', disk_gb: '10', tags: '' };

        // Add custom image: an image of one's own for the library, the body the classic dialog sends
        function CrImgAdd({ authFetch, onCancel, onAdded }) {
            const { t } = useTranslation();
            const [form, setForm] = useState(CR_IMG_ADD_EMPTY);
            const [tried, setTried] = useState(false);
            const [busy, setBusy] = useState(false);
            const [server, setServer] = useState('');
            const set = (k, v) => setForm(f => ({ ...f, [k]: v }));
            const errs = {};
            if (!form.name.trim()) errs.name = t('crImgErrRequired');
            if (!form.image_url.trim()) errs.image_url = t('crImgErrRequired');
            else if (!/^https?:\/\/\S+$/i.test(form.image_url.trim())) errs.image_url = t('crImgErrUrl');
            ['cores', 'memory', 'disk_gb'].forEach(k => { if (!(crImgInt(form[k]) >= 1)) errs[k] = t('crImgErrNumber'); });
            const err = (k) => (tried ? errs[k] || '' : '');
            const go = async () => {
                setTried(true);
                setServer('');
                if (Object.keys(errs).length) return;
                const body = {
                    name: form.name.trim(), description: form.description.trim(), distro: form.distro.trim() || 'custom',
                    version: form.version.trim(), image_url: form.image_url.trim(), default_user: form.default_user.trim() || 'root',
                    cores: crImgInt(form.cores), memory: crImgInt(form.memory), disk_gb: crImgInt(form.disk_gb),
                    tags: form.tags.split(',').map(s => s.trim()).filter(Boolean),
                };
                setBusy(true);
                const res = await crImgSend(authFetch, `${API_URL}/templates/custom`, 'POST', body);
                setBusy(false);
                if (res.ok && res.body && res.body.template) { onAdded(res.body.template); return; }
                setServer(crImgSendText(res, t));
            };
            const input = (k, extra = {}) => (
                <input id={`cr-nc-img-${k}`} className="cr-input" value={form[k]} spellCheck={false} onChange={e => set(k, e.target.value)} data-cr-img-a={k} {...extra} />
            );
            return (
                <CrUpdDialog id="img-add" sticky busy={busy} onCancel={onCancel} title={t('crImgAddTitle')}
                    footer={(
                        <>
                            <CrButton onClick={onCancel} disabled={busy} data-cr-img-add-cancel="">{t('cancel')}</CrButton>
                            <CrButton variant="primary" onClick={go} disabled={busy} data-cr-img-add-go="">{busy ? t('crNcSaving') : t('crImgAddGo')}</CrButton>
                        </>
                    )}>
                    <div className="cr-img-dialog" data-cr-img-add-form="">
                        <p className="cr-img-fine">{t('crImgAddDesc')}</p>
                        {server && <CrUpdNote tone="error" id="img-add">{server}</CrUpdNote>}
                        <div className="cr-nc-form">
                            <CrImgField id="name" label={t('crImgFImgName')} error={err('name')}>{input('name', { maxLength: 100 })}</CrImgField>
                            <CrImgField id="default_user" label={t('crImgFUser')}>{input('default_user', { maxLength: 32 })}</CrImgField>
                            <CrImgField id="image_url" label={t('crImgFUrl')} wide error={err('image_url')} hint={t('crImgFUrlHint')}>
                                {input('image_url', { type: 'url', className: 'cr-input cr-nc-mono-input', placeholder: 'https://cloud-images.example.com/image.qcow2' })}
                            </CrImgField>
                            <CrImgField id="description" label={t('crImgFDesc')} wide>{input('description', { maxLength: 300 })}</CrImgField>
                            <CrImgField id="distro" label={t('crImgFDistro')}>{input('distro', { placeholder: 'ubuntu, debian, ...' })}</CrImgField>
                            <CrImgField id="version" label={t('crImgFVersion')}>{input('version', { placeholder: '24.04' })}</CrImgField>
                        </div>
                        <div className="cr-nc-form cr-img-nums">
                            <CrImgField id="cores" label={t('crImgFCores')} error={err('cores')}>{input('cores', { inputMode: 'numeric' })}</CrImgField>
                            <CrImgField id="memory" label={t('crImgFMemory')} error={err('memory')}>{input('memory', { inputMode: 'numeric' })}</CrImgField>
                            <CrImgField id="disk_gb" label={t('crImgFDisk')} error={err('disk_gb')}>{input('disk_gb', { inputMode: 'numeric' })}</CrImgField>
                        </div>
                        <div className="cr-nc-form">
                            <CrImgField id="tags" label={t('crImgFTags')} wide hint={t('crImgFTagsHint')}>{input('tags', { placeholder: 'lts, internal' })}</CrImgField>
                        </div>
                    </div>
                </CrUpdDialog>
            );
        }

        // --- the images ----------------------------------------------------------------------------

        // canAct: the library's own buttons (build, add, delete), an administrator's as in the classic tab.
        // pve: the cluster is a Proxmox VE one (the library builds its templates there only); room: see CR_IMG_WIDE
        function CrImages({ cluster, authFetch, addToast, cat, existing, builds, bps, canRead, write, canAct, pve, room, onNewBlueprint,
                            onRefresh, onBuilt, onChanged }) {
            const { t } = useTranslation();
            const { haReadOnly } = useAuth();
            const [build, setBuild] = useState(null);
            const [add, setAdd] = useState(false);
            const [del, setDel] = useState(null);
            const [delBusy, setDelBusy] = useState(false);
            const libWhy = canAct ? undefined : t(haReadOnly ? 'crImgStandby' : 'crImgAdminOnly');
            const buildWhy = !pve ? t('crImgNotPve') : libWhy;
            const bpWhy = write ? undefined : t(haReadOnly ? 'crImgStandby' : 'crImgNeedsPerm');
            const wide = room === 'wide';
            const narrow = room === 'narrow';
            const unread = !pve ? '' : existing.state === 'error' ? existing.why : builds.state === 'error' ? builds.why : '';
            const reading = existing.state === 'loading' || builds.state === 'loading';
            const used = (img) => bps.rows.filter(b => b && b.template_id === img.id).length;
            const tagsOf = (img) => (Array.isArray(img.tags) ? img.tags : []).filter(x => x && !(img.custom && x === 'custom'));
            const hereOf = (img) => crImgHere(img, builds.rows, existing.rows);

            const remove = async () => {
                if (!del) return;
                setDelBusy(true);
                const res = await crImgSend(authFetch, `${API_URL}/templates/custom/${encodeURIComponent(del.id)}`, 'DELETE');
                setDelBusy(false);
                if (res.ok) { setDel(null); addToast(t('crImgDeleted'), 'success'); onChanged(); return; }
                addToast(crImgSendText(res, t), 'error');
            };

            const cols = [
                { key: 'name', label: t('crImgColImage'), flex: true, min: 160, sortValue: r => r.name || '', text: r => `${r.name || ''} ${r.description || ''}`,
                  render: r => (
                    <span className="cr-img-name" data-cr-img-row={r.id} title={[r.name, r.description].filter(Boolean).join('\n')}>
                        <span className="cr-strong">{r.name}</span>
                        {/* Custom on the second line: the name keeps the room of the first */}
                        {(r.custom || r.description) && (
                            <span className="cr-img-desc">
                                {r.custom && <span data-cr-img-custom=""><CrBadge tone="neutral" dot={false}>{t('crImgCustom')}</CrBadge></span>}
                                {r.description}
                            </span>
                        )}
                    </span>) },
                // the default user under the hardware: one column less, so the actions stay in view at 1280 px
                { key: 'spec', label: t('crImgColSpec'), width: 144, sortable: false, hidden: narrow, text: r => `${crImgSpec(r)} ${r.default_user || ''}`, render: r => (
                    <span className="cr-img-name">
                        <span className="cr-img-spec">{crImgSpec(r)}</span>
                        {r.default_user && <span className="cr-img-desc" data-cr-img-user={r.default_user}>{crFill(t('crImgSpecUser'), { user: r.default_user })}</span>}
                    </span>) },
                { key: 'tags', label: t('crImgColTags'), flex: true, min: 100, sortable: false, hidden: narrow, text: r => tagsOf(r).join(' '), render: r => (
                    <span className="cr-img-tags" title={tagsOf(r).join(', ') || undefined}>{tagsOf(r).map(x => <CrBadge key={x} tone="neutral" dot={false}>{x}</CrBadge>)}</span>) },
                { key: 'here', label: t('crImgColHere'), width: 164, title: t('crImgColHereTitle'), sortValue: r => (pve ? crImgHereRank(hereOf(r)) : 0),
                  render: r => (pve && reading ? <span className="cr-muted">{t('crNcReading')}</span> : <CrImgHere here={hereOf(r)} unread={unread} pve={pve} />) },
                canRead && { key: 'used', label: t('crImgColUsed'), width: 88, align: 'right', hidden: narrow, title: t('crImgColUsedTitle'), sortValue: used,
                             render: r => (bps.state === 'ok' ? <span data-cr-img-used={used(r)}>{used(r)}</span> : '') },
                { key: 'act', label: '', width: wide ? 300 : 190, sortable: false, render: r => (
                    <span className="cr-img-acts">
                        <CrButton className="cr-btn-xs" icon={<Icons.Plus />} disabled={!write} title={bpWhy}
                            onClick={e => { e.stopPropagation(); onNewBlueprint(r.id); }} data-cr-img-new={r.id}>{t('crImgNewBp')}</CrButton>
                        <CrButton className="cr-btn-xs" variant="ghost" icon={<Icons.Download />} disabled={!canAct || !pve}
                            title={buildWhy || (wide ? undefined : t('crImgBuild'))} aria-label={wide ? undefined : t('crImgBuild')}
                            onClick={e => { e.stopPropagation(); setBuild(r); }} data-cr-img-build={r.id}>{wide ? t('crImgBuild') : null}</CrButton>
                        {r.custom && (
                            <CrButton className="cr-btn-xs" variant="danger" icon={<Icons.Trash2 />} disabled={!canAct}
                                title={libWhy || crFill(t('crImgDeleteTitle'), { name: r.name })} aria-label={crFill(t('crImgDeleteTitle'), { name: r.name })}
                                onClick={e => { e.stopPropagation(); setDel(r); }} data-cr-img-delete={r.id} />
                        )}
                    </span>) },
            ].filter(Boolean);

            return (
                <CrNcSection id="img" title={t('crImgTitle')} desc={t('crImgDesc')} data-cr-img=""
                    badge={cat.state === 'ok' ? <CrBadge tone="neutral" dot={false}>{cat.rows.length}</CrBadge> : null}
                    actions={(
                        <>
                            <CrButton icon={<Icons.Plus />} disabled={!canAct} title={libWhy} onClick={() => setAdd(true)} data-cr-img-add="">{t('crImgAdd')}</CrButton>
                            <CrButton className="cr-btn-xs" icon={<Icons.RefreshCw />} onClick={onRefresh} title={t('crImgRefreshTitle')} data-cr-img-refresh="">{t('refresh')}</CrButton>
                        </>
                    )}>
                    {haReadOnly && <CrNcState id="img-standby" kind="info">{t('crImgStandby')}</CrNcState>}
                    {!haReadOnly && !canAct && <p className="cr-img-fine" data-cr-img-adminonly="">{t('crImgAdminOnly')}</p>}
                    {/* the library first: what this cluster has of it only counts with the images there */}
                    {cat.state === 'loading' ? <CrNcState id="img" kind="loading" />
                        : cat.state === 'error' ? <CrNcState id="img" kind="error" onRetry={onRefresh} data-cr-img-error="">{crFill(t('crImgReadFailed'), { reason: cat.why })}</CrNcState>
                        : !cat.rows.length ? <CrNcState id="img-empty" kind="info" data-cr-img-empty="">{t('crImgEmpty')}</CrNcState>
                        : (
                            <>
                                {unread && <CrNcState id="img-here" kind="warning" onRetry={onRefresh}>{crFill(t('crImgHereFailedRead'), { reason: unread })}</CrNcState>}
                                <CrTable id="img-list" columns={cols} rows={cat.rows} rowKey={r => r.id} ariaLabel={t('crImgTitle')} rowHeight={40} showCount={false} />
                            </>
                        )}
                    {build && (
                        <CrImgBuild img={build} cluster={cluster} authFetch={authFetch} onCancel={() => setBuild(null)}
                            onStarted={(res) => { setBuild(null); onBuilt(res); }} />
                    )}
                    {add && <CrImgAdd authFetch={authFetch} onCancel={() => setAdd(false)} onAdded={() => { setAdd(false); addToast(t('crImgAdded'), 'success'); onChanged(); }} />}
                    {del && (
                        <CrNcConfirm id="img-delete" title={crFill(t('crImgDeleteTitle'), { name: del.name })} goLabel={t('delete')} busy={delBusy}
                            onCancel={() => setDel(null)} onConfirm={remove}>
                            <p>{t('crImgDeleteText')}</p>
                            {used(del) > 0 && <CrUpdNote tone="warning" id="img-delete-used">{crFill(t('crImgDeleteUsed'), { n: used(del) })}</CrUpdNote>}
                        </CrNcConfirm>
                    )}
                </CrNcSection>
            );
        }

        // --- the recent deploys --------------------------------------------------------------------

        // This cluster: the rows the page reads (deploys, builds). All clusters: the blueprint deploys of
        // every cluster in one read and the template builds of each Proxmox VE cluster, read here when
        // picked, on Refresh and after a deploy the blueprints started (ran counts those). The rows of
        // this cluster are the page's own there too, so they follow a running one
        function CrImgRecent({ cid, clusters, authFetch, nav, deploys, builds, ran, onRefresh }) {
            const { t } = useTranslation();
            const [scope, setScope] = useState('cluster');
            const [all, setAll] = useState(null);
            const seq = useRef(0);
            const pve = (clusters || []).filter(crImgPve);
            const byId = new Map((clusters || []).map(c => [c.id, c]));

            const readAll = () => {
                const my = ++seq.current;
                const ids = pve.map(c => c.id);
                const acc = { rows: [], failed: [], done: 0 };
                const flush = () => setAll(a => ({ ...a, tpl: { n: ids.length, done: acc.done, rows: acc.rows.slice(), failed: acc.failed.slice() } }));
                setAll({ at: Date.now(), bp: { state: 'loading', rows: [], why: '' }, tpl: { n: ids.length, done: 0, rows: [], failed: [] } });
                crDriftRead(authFetch, `${API_URL}/blueprints/deployments`).then(read => {
                    if (my === seq.current) setAll(a => ({ ...a, bp: crImgList(read, 'deployments', t) }));
                });
                let next = 0;
                const worker = async () => {
                    while (next < ids.length) {
                        const id = ids[next++];
                        const read = await crDriftRead(authFetch, `${API_URL}/clusters/${encodeURIComponent(id)}/templates/deployments`);
                        if (my !== seq.current) return;
                        acc.done += 1;
                        if (read.state === 'ok') acc.rows.push(...(Array.isArray(read.body.deployments) ? read.body.deployments : []).map(r => ({ ...r, cluster_id: r.cluster_id || id })));
                        else acc.failed.push({ id, why: crDriftReadText(read, t) });
                        // a render per ten clusters, not per cluster
                        if (acc.done === ids.length || acc.done % 10 === 0) flush();
                    }
                };
                for (let i = 0; i < Math.min(CR_IMG_PARALLEL, ids.length); i++) worker();
            };
            useEffect(() => () => { seq.current += 1; }, []);
            // a deploy onto another cluster shows up in All clusters only with a new read
            useEffect(() => { if (ran && scope === 'all') readAll(); }, [ran]);
            const pick = (s) => {
                setScope(s);
                if (s === 'all' && !all) readAll();
            };
            const refresh = () => (scope === 'all' ? readAll() : onRefresh());

            const inAll = scope === 'all';
            const bpRead = inAll ? (all ? all.bp : { state: 'loading', rows: [], why: '' }) : deploys;
            const merged = useMemo(() => {
                if (!inAll) return crImgMerge(deploys.rows, builds.rows);
                if (!all) return [];
                const withHere = (list, here) => (here.state !== 'ok' ? list
                    : list.filter(r => r.cluster_id !== cid).concat(here.rows.map(r => ({ ...r, cluster_id: r.cluster_id || cid }))));
                return crImgMerge(all.bp.state === 'ok' ? withHere(all.bp.rows, deploys) : [], withHere(all.tpl.rows, builds));
            }, [inAll, all, deploys, builds, cid]);
            const rows = merged.slice(0, CR_IMG_RECENT_MAX);
            const loading = inAll ? (!all || bpRead.state === 'loading' || all.tpl.done < all.tpl.n) : (deploys.state === 'loading' || builds.state === 'loading');
            const failed = inAll ? (all ? all.tpl.failed : []) : (builds.state === 'error' ? [{ id: cid, why: builds.why }] : []);

            const open = (r) => nav.openGuest(r.cid, { vmid: Number(r.vmid), node: r.node, type: 'qemu', name: r.name || '' });
            // From and State share the room: at 1280 px a State with the reason of a failure is about 200 px
            const cols = [
                { key: 'kind', label: t('crImgColKind'), width: 120, sortValue: r => r.kind, render: r => (
                    <span data-cr-img-kind={r.kind}>{t(r.kind === 'vm' ? 'crImgKindVm' : 'crImgKindTpl')}</span>) },
                { key: 'what', label: t('crImgColWhat'), flex: true, min: 140, sortValue: r => r.what, text: r => `${r.what} ${r.forBp}`, render: r => (
                    <span className="cr-img-what" title={r.forBp ? crFill(t('crImgForBp'), { name: r.forBp }) : undefined}>
                        <span>{r.what}</span>
                        {r.forBp && <span className="cr-muted">{crFill(t('crImgForBp'), { name: r.forBp })}</span>}
                    </span>) },
                { key: 'guest', label: t('crImgColGuest'), width: 136, sortValue: r => Number(r.vmid) || 0, render: r => {
                    const label = r.kind === 'tpl' ? crFill(t('crImgTplVmid'), { vmid: r.vmid ?? '' }) : r.name ? `${r.name} (${r.vmid})` : String(r.vmid ?? '');
                    // a guest a deploy finished opens; a template is no guest to work on
                    return r.kind === 'vm' && r.status === 'completed' && r.vmid && nav && typeof nav.openGuest === 'function'
                        ? <button type="button" className="cr-link" data-cr-img-guest={r.vmid} onClick={e => { e.stopPropagation(); open(r); }}>{label}</button>
                        : <span className="cr-mono">{label}</span>;
                } },
                inAll && { key: 'cluster', label: t('crImgColCluster'), width: 110, sortValue: r => crImgName(byId.get(r.cid)) || r.cid,
                           render: r => <span data-cr-img-cluster={r.cid}>{crImgName(byId.get(r.cid)) || r.cid}</span> },
                { key: 'node', label: t('crImgColNode'), width: 80, sortValue: r => r.node, render: r => r.node },
                { key: 'state', label: t('crImgColState'), flex: true, min: 150, sortValue: r => r.status, render: r => <CrImgState row={r} /> },
                { key: 'at', label: t('crImgColStarted'), width: 132, sortValue: r => r.started_at,
                  render: r => (r.started_at ? <span title={t('crDriftServerTime')}>{crDriftTime(String(r.started_at))}</span> : '') },
                { key: 'by', label: t('crImgColBy'), width: 84, sortValue: r => r.started_by, render: r => <span title={r.started_by || undefined}>{r.started_by}</span> },
            ].filter(Boolean);

            return (
                <CrNcSection id="img-recent" title={t('crImgRecentTitle')} desc={t('crImgRecentDesc')} data-cr-img-recent={scope}
                    actions={<CrButton className="cr-btn-xs" icon={<Icons.RefreshCw />} onClick={refresh} data-cr-img-recent-refresh="">{t('refresh')}</CrButton>}>
                    <div className="cr-img-tools">
                        <div className="cr-seg" role="group" aria-label={t('crImgScope')}>
                            <button type="button" className={inAll ? '' : 'active'} aria-pressed={!inAll} onClick={() => pick('cluster')}
                                data-cr-img-scope="cluster">{t('crImgScopeHere')}</button>
                            <button type="button" className={inAll ? 'active' : ''} aria-pressed={inAll} onClick={() => pick('all')}
                                data-cr-img-scope="all">{t('crImgScopeAll')}</button>
                        </div>
                        {inAll && all && (
                            <span className="cr-muted" data-cr-img-cover={`${all.tpl.done}/${all.tpl.n}`}>
                                {all.tpl.done < all.tpl.n ? crFill(t('crImgRecentReading'), { done: all.tpl.done, n: all.tpl.n })
                                    : `${crFill(t('crImgRecentCover'), { ok: all.tpl.n - all.tpl.failed.length, n: all.tpl.n })} ${
                                        crFill(t('crTaskJobsReadAt'), { time: crFmtTime(all.at) })}`}
                            </span>
                        )}
                    </div>
                    {bpRead.state === 'error' && <CrNcState id="img-recent-bp" kind="warning" onRetry={refresh}>{crFill(t('crImgRecentBpFailed'), { reason: bpRead.why })}</CrNcState>}
                    {failed.length > 0 && (
                        <CrNcState id="img-recent-tpl" kind="warning" onRetry={refresh} data-cr-img-unread={failed.map(f => f.id).join(',')}>
                            {crFill(t('crImgRecentTplFailed'), { reason: failed.map(f => (inAll ? `${crImgName(byId.get(f.id)) || f.id} (${f.why})` : f.why)).join(', ') })}
                        </CrNcState>
                    )}
                    {loading && !rows.length ? <CrNcState id="img-recent" kind="loading" />
                        : !rows.length ? <p className="cr-img-fine" data-cr-img-recent-empty="">{t(inAll ? 'crImgRecentNoneAll' : 'crImgRecentNone')}</p>
                        : <CrTable key={scope} id={inAll ? 'img-recent-all' : 'img-recent'} columns={cols} rows={rows} rowKey={r => r.key}
                            ariaLabel={t('crImgRecentTitle')} rowHeight={30} columnMenu={false} showCount={false} loading={loading}
                            initialSort={{ key: 'at', dir: 'desc' }} />}
                    {merged.length > rows.length && <p className="cr-img-fine">{crFill(t('crImgRecentNewest'), { max: rows.length, n: merged.length })}</p>}
                </CrNcSection>
            );
        }

        // --- the page ------------------------------------------------------------------------------

        // canRead: the account holds vm.create (the blueprint routes ask for it); canWrite: it may use it
        // here; isAdmin: the library's buttons, as the classic tab has them. nav: the task center's
        // navigation, for the guests and templates in the list
        function CrBlueprintsTab({ cluster, clusters, authFetch, addToast, canRead, canWrite, isAdmin, nav }) {
            const { t } = useTranslation();
            const { haReadOnly } = useAuth();
            const cid = cluster && cluster.id;
            const shared = useMemo(() => crImgShared(authFetch), [authFetch]);
            const [cat, setCat] = useState({ state: 'loading', rows: [], why: '' });
            const [existing, setExisting] = useState({ state: 'loading', rows: [], why: '' });
            const [builds, setBuilds] = useState({ state: 'loading', rows: [], why: '' });
            const [deploys, setDeploys] = useState({ state: 'loading', rows: [], why: '' });
            const [bps, setBps] = useState({ state: 'idle', rows: [] });
            const [prefill, setPrefill] = useState('');
            // bpKey draws the blueprints anew (they read their list when they mount), ran counts the
            // deploys they started
            const [bpKey, setBpKey] = useState(0);
            const [ran, setRan] = useState(0);
            const [room, setRoom] = useState('wide');
            const pageRef = useRef(null);
            const wasLive = useRef(false);
            const write = canWrite && !haReadOnly;
            const canAct = isAdmin && !haReadOnly;
            const pve = crImgPve(cluster);

            useEffect(() => {
                const el = pageRef.current;
                if (!el || typeof ResizeObserver === 'undefined') return undefined;
                const fit = () => setRoom(el.clientWidth >= CR_IMG_WIDE ? 'wide' : el.clientWidth >= CR_IMG_NARROW ? 'compact' : 'narrow');
                const ro = new ResizeObserver(fit);
                ro.observe(el);
                fit();
                return () => ro.disconnect();
            }, []);

            const readCatalog = () => crDriftRead(shared, `${API_URL}/templates/catalog`).then(r => setCat(crImgList(r, 'templates', t)));
            const readBps = () => {
                if (!canRead) return;
                crDriftRead(shared, `${API_URL}/blueprints`).then(r => setBps(crImgList(r, 'blueprints', t)));
            };
            // the templates of this cluster, the library's builds and the blueprint deploys onto it.
            // An XCP-ng pool has none of them: the library builds and blueprints deploy on Proxmox VE only
            const readHere = () => {
                if (!cid) return;
                if (!pve) {
                    const none = { state: 'ok', rows: [], why: '' };
                    setExisting(none);
                    setBuilds(none);
                    setDeploys(none);
                    return;
                }
                const base = `${API_URL}/clusters/${encodeURIComponent(cid)}`;
                crDriftRead(shared, `${base}/templates/existing`).then(r => setExisting(crImgList(r, 'templates', t)));
                crDriftRead(shared, `${base}/templates/deployments`).then(r => setBuilds(crImgList(r, 'deployments', t)));
                crDriftRead(shared, `${API_URL}/blueprints/deployments?cluster_id=${encodeURIComponent(cid)}`).then(r => setDeploys(crImgList(r, 'deployments', t)));
            };
            useEffect(() => { readCatalog(); readHere(); readBps(); }, []);

            // read again while something of this cluster runs, and once after the last one ended:
            // the template list of the cluster can be a moment behind the build that made it
            const live = builds.rows.some(crImgLive) || deploys.rows.some(crImgLive);
            useEffect(() => {
                const again = live || wasLive.current;
                wasLive.current = live;
                if (!again) return undefined;
                const timer = setTimeout(readHere, CR_IMG_POLL);
                return () => clearTimeout(timer);
            }, [live, builds, deploys]);

            // New blueprint of an image row opens the editor of the blueprints with it. Cleared once they
            // had it (their effects run before this one), so the same image can be picked again
            useEffect(() => { if (prefill) setPrefill(''); }, [prefill]);

            // the Refresh of the images reads the page: the blueprints mount again and read their list
            // in the same request as Used by
            const refresh = () => { readCatalog(); readHere(); readBps(); setBpKey(k => k + 1); };
            const built = (res) => {
                addToast(t('crImgBuildStarted'), 'success');
                if (res && res.quota_warning) addToast(crFill(t('crImgQuota'), { msg: String(res.quota_warning) }), 'warning');
                readHere();
            };
            // a deploy the server took: Recent deploys lists it and reads it again while it runs
            const deployed = () => { readHere(); setRan(n => n + 1); };
            return (
                <div className="cr-img-page" ref={pageRef} data-cr-img-page="" data-cr-img-room={room}>
                    <CrBoundary id="bp-blueprints">
                        <CrBlueprints key={bpKey} cluster={cluster} clusters={clusters} authFetch={shared} addToast={addToast}
                            canRead={canRead} canWrite={canWrite} nav={nav} prefillTemplate={prefill}
                            onSaved={readBps} onDeleted={readBps} onDeployed={deployed} />
                    </CrBoundary>
                    <CrBoundary id="bp-images">
                        <CrImages cluster={cluster} authFetch={shared} addToast={addToast} cat={cat} existing={existing} builds={builds} bps={bps}
                            canRead={canRead} write={write} canAct={canAct} pve={pve} room={room} onNewBlueprint={setPrefill} onRefresh={refresh}
                            onBuilt={built} onChanged={() => { readCatalog(); readBps(); }} />
                    </CrBoundary>
                    <CrBoundary id="bp-recent">
                        <CrImgRecent cid={cid} clusters={clusters} authFetch={shared} nav={nav} deploys={deploys} builds={builds} ran={ran}
                            onRefresh={readHere} />
                    </CrBoundary>
                </div>
            );
        }
