        // A central catalog; each connection can be an independent Proxmox host.
        function ImagesAndTemplatesTab(props) {
            const [view, setView] = React.useState('images');
            return <div className="space-y-4">
                <div className="flex gap-2">
                    {[['images', 'centralImages'], ['templates', 'templateLibrary']].map(([id, key]) =>
                        <button key={id} onClick={() => setView(id)}
                            className={`px-3 py-2 rounded-lg text-sm ${view === id ? 'bg-proxmox-orange text-white' : 'bg-proxmox-card border border-proxmox-border'}`}>
                            {props.t(key)}
                        </button>)}
                </div>
                {view === 'images' ? <CentralImageLibraryTab {...props} /> : <TemplatesLibraryTab {...props} />}
            </div>;
        }

        function CentralImageLibraryTab({ clusterId, clusters = [], authFetch, addToast, t, isAdmin }) {
            const { haReadOnly } = useAuth();
            const canAct = isAdmin && !haReadOnly;
            const connections = clusters.filter(c => (c.cluster_type || 'proxmox') === 'proxmox');
            const [target, setTarget] = React.useState(clusterId || connections[0]?.id || '');
            const [images, setImages] = React.useState([]);
            const [jobs, setJobs] = React.useState([]);
            const [jobVersion, setJobVersion] = React.useState(0);
            const [search, setSearch] = React.useState('');
            const [error, setError] = React.useState('');
            const [loading, setLoading] = React.useState(true);
            const [busy, setBusy] = React.useState(false);
            const [importing, setImporting] = React.useState(false);
            const [importForm, setImportForm] = React.useState({ name: '', kind: 'iso', mode: 'upload', source_url: '', sha256: '', default_user: 'root' });
            const [file, setFile] = React.useState(null);
            const [selected, setSelected] = React.useState(null);
            const [form, setForm] = React.useState({});
            const [nodes, setNodes] = React.useState([]);
            const [options, setOptions] = React.useState({ storages: [], bridges: [] });
            const [targetsLoading, setTargetsLoading] = React.useState(false);
            const inputClass = 'w-full px-3 py-2 bg-proxmox-dark border border-proxmox-border rounded-lg text-sm';
            const buttonClass = 'px-3 py-2 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white disabled:opacity-50';
            const field = (label, control) => <label className="block text-sm space-y-1"><span className="text-gray-400">{label}</span>{control}</label>;
            const change = (key, value) => setForm(f => ({ ...f, [key]: value }));
            const readJSON = async (path, init) => {
                const response = await authFetch(`${API_URL}${path}`, init);
                if (!response) throw new Error(t('centralRequestFailed'));
                const data = await response.json();
                if (!response.ok) throw new Error(data.error || t('centralRequestFailed'));
                return data;
            };
            const reload = async () => {
                setLoading(true);
                try { setImages((await readJSON('/images')).images || []); }
                catch (e) { setError(e.message); }
                finally { setLoading(false); }
            };
            React.useEffect(() => { reload(); }, []);
            React.useEffect(() => {
                if (!connections.some(c => c.id === target)) setTarget(connections[0]?.id || '');
            }, [clusters, target]);
            React.useEffect(() => {
                let current = true;
                setJobs([]);
                if (!target || !isAdmin) return;
                const poll = async () => {
                    try {
                        const data = await readJSON(`/clusters/${encodeURIComponent(target)}/images/jobs`);
                        if (current) setJobs(data.jobs || []);
                    } catch (e) { if (current) setError(e.message); }
                };
                poll();
                const timer = setInterval(poll, 4000);
                return () => { current = false; clearInterval(timer); };
            }, [target, isAdmin, jobVersion]);
            React.useEffect(() => {
                let current = true;
                setNodes([]);
                setOptions({ storages: [], bridges: [] });
                if (!selected || !target) return;
                setTargetsLoading(true);
                change('node', '');
                readJSON(`/clusters/${encodeURIComponent(target)}/images/targets`).then(data => {
                    if (!current) return;
                    setNodes(data.nodes || []);
                    change('node', data.nodes?.[0] || '');
                }).catch(e => { if (current) setError(e.message); })
                  .finally(() => { if (current) setTargetsLoading(false); });
                return () => { current = false; };
            }, [selected, target]);
            React.useEffect(() => {
                let current = true;
                setOptions({ storages: [], bridges: [] });
                change('storage', ''); change('bridge', ''); change('iso_storage', '');
                if (!selected || !target || !form.node) return;
                setTargetsLoading(true);
                readJSON(`/clusters/${encodeURIComponent(target)}/images/targets?node=${encodeURIComponent(form.node)}`).then(data => {
                    if (!current) return;
                    setOptions(data);
                    const disks = data.storages.filter(s => s.content.split(',').includes('images'));
                    const isos = data.storages.filter(s => s.content.split(',').includes('iso'));
                    change('storage', disks.find(s => s.storage === 'local-lvm')?.storage || disks[0]?.storage || '');
                    change('iso_storage', isos[0]?.storage || '');
                    change('bridge', data.bridges.includes('vmbr0') ? 'vmbr0' : data.bridges[0] || '');
                }).catch(e => { if (current) setError(e.message); })
                  .finally(() => { if (current) setTargetsLoading(false); });
                return () => { current = false; };
            }, [selected, target, form.node]);
            React.useEffect(() => {
                const escape = e => { if (e.key === 'Escape' && !busy) { setSelected(null); setImporting(false); } };
                document.addEventListener('keydown', escape);
                return () => document.removeEventListener('keydown', escape);
            }, [busy]);
            const openCreate = image => {
                setError('');
                setForm({ name: '', node: '', storage: '', bridge: '', iso_storage: '', ostype: 'l26',
                    cores: image.cores || 2, memory: image.memory || 2048, disk_gb: image.disk_gb || 20,
                    ciuser: image.default_user || 'root', sshkeys: '', start: true, vmid: '' });
                setSelected(image);
            };
            const importImage = async e => {
                e.preventDefault(); setBusy(true); setError('');
                try {
                    if (importForm.mode === 'upload') {
                        if (!file) throw new Error(t('centralSelectFile'));
                        const body = new FormData();
                        ['name', 'kind', 'sha256', 'default_user'].forEach(key => body.append(key, importForm[key]));
                        body.append('file', file);
                        await readJSON('/images/upload', { method: 'POST', body });
                    } else {
                        await readJSON('/images', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(importForm) });
                    }
                    setImporting(false); setFile(null); await reload();
                    addToast(t('centralImported'), 'success');
                } catch (e) { setError(e.message); }
                finally { setBusy(false); }
            };
            const createVM = async e => {
                e.preventDefault(); setBusy(true); setError('');
                try {
                    await readJSON(`/clusters/${encodeURIComponent(target)}/images/provision`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ...form, image_id: selected.id }),
                    });
                    setSelected(null); setJobVersion(v => v + 1);
                    addToast(t('centralQueued'), 'success');
                } catch (e) { setError(e.message); }
                finally { setBusy(false); }
            };
            const removeImage = async image => {
                if (!window.confirm(`${t(image.builtin ? 'centralClearCacheConfirm' : 'centralDeleteConfirm')} ${image.name}?`)) return;
                setBusy(true); setError('');
                try { await readJSON(`/images/${image.id}`, { method: 'DELETE' }); await reload(); }
                catch (e) { setError(e.message); }
                finally { setBusy(false); }
            };
            const connectionSelect = <select aria-label={t('centralConnection')} value={target} disabled={busy} onChange={e => { setError(''); setTarget(e.target.value); }} className={inputClass}>
                {!connections.length && <option value="">{t('centralNoConnections')}</option>}
                {connections.map(c => <option key={c.id} value={c.id}>{c.name || c.id}</option>)}
            </select>;
            const storageSelect = (key, content) => <select required value={form[key] || ''} onChange={e => change(key, e.target.value)} className={inputClass}>
                <option value="">{t('centralSelectStorage')}</option>
                {options.storages.filter(s => s.content.split(',').includes(content)).map(s => <option key={s.storage} value={s.storage}>{s.storage}</option>)}
            </select>;
            const errorBox = error && <p role="alert" className="p-3 rounded-lg bg-red-500/10 text-red-400 text-sm break-words">{error}</p>;
            return <div className="space-y-4">
                <div className="flex flex-wrap justify-between gap-3">
                    <div><h2 className="text-lg font-semibold">{t('centralImages')}</h2><p className="text-sm text-gray-400 mt-1">{t('centralImagesDesc')}</p></div>
                    <div className="flex gap-2 items-start">
                        {canAct && <button className={buttonClass} disabled={busy} onClick={() => { setError(''); setFile(null); setImportForm({ name: '', kind: 'iso', mode: 'upload', source_url: '', sha256: '', default_user: 'root' }); setImporting(true); }}>{t('centralAddImage')}</button>}
                        <button className="px-3 py-2 rounded-lg border border-proxmox-border text-sm" disabled={loading || busy} onClick={reload}>{t('refresh')}</button>
                    </div>
                </div>
                {!selected && !importing && errorBox}
                <input aria-label={t('search')} placeholder={t('search')} value={search} onChange={e => setSearch(e.target.value)} className={inputClass} />
                {loading && <p className="text-sm text-gray-400">{t('loading')}</p>}
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                    {images.filter(image => image.name.toLowerCase().includes(search.toLowerCase())).map(image => <div key={image.id} className="bg-proxmox-card border border-proxmox-border rounded-xl p-4 flex flex-col gap-3">
                        <div className="flex justify-between gap-2"><h3 className="font-semibold break-words">{image.name}</h3><span className="text-xs text-gray-400 whitespace-nowrap">{image.kind === 'iso' ? 'ISO' : 'Cloud-init'}</span></div>
                        <p className="text-xs text-gray-400">{t(image.cached ? 'centralCached' : 'centralDownloadOnUse')}{image.size > 0 && ` · ${(image.size / 1073741824).toFixed(2)} GiB`}</p>
                        {image.description && <p className="text-xs text-gray-400">{image.description}</p>}
                        {image.cpu && <p className="text-xs text-gray-400">CPU: {image.cpu}</p>}
                        <div className="flex gap-2 mt-auto">
                            <button className={`${buttonClass} flex-1`} disabled={!canAct || busy || !target} onClick={() => openCreate(image)}>{t('centralCreateVM')}</button>
                            {canAct && (!image.builtin || image.cached) && <button title={t(image.builtin ? 'centralClearCache' : 'delete')} aria-label={t(image.builtin ? 'centralClearCache' : 'delete')} className="p-2 text-gray-400 hover:text-red-400" disabled={busy} onClick={() => removeImage(image)}><Icons.Trash2 /></button>}
                        </div>
                    </div>)}
                </div>
                {isAdmin && <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4 space-y-3">
                    <div className="flex flex-wrap gap-3 justify-between items-center"><h3 className="font-semibold">{t('centralJobs')}</h3><div className="max-w-sm">{connectionSelect}</div></div>
                    {!jobs.length && <p className="text-sm text-gray-400">{t('centralNoJobs')}</p>}
                    {jobs.map(job => <div key={job.id} className="border-t border-proxmox-border pt-3 space-y-1">
                        <div className="flex flex-wrap justify-between gap-2 text-sm"><span>{job.name} · {job.node}{job.vmid && ` · VM ${job.vmid}`}</span><span>{t(`centralJob_${job.status}`)} · {job.progress}%</span></div>
                        <p className="text-xs text-gray-400">{job.image_name} · {new Date(job.started_at).toLocaleString()}</p>
                        <div className="h-1 rounded bg-proxmox-dark"><div className={`h-1 rounded ${job.status === 'failed' ? 'bg-red-500' : 'bg-proxmox-orange'}`} style={{ width: `${job.progress}%` }} /></div>
                        {job.error && <p className="text-sm text-red-400 break-words">{job.error}</p>}
                    </div>)}
                </div>}
                {(importing || selected) && <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={() => { if (!busy) { setImporting(false); setSelected(null); } }}>
                    <form role="dialog" aria-modal="true" aria-labelledby="central-image-dialog-title" onSubmit={importing ? importImage : createVM} onClick={e => e.stopPropagation()} className="bg-proxmox-card border border-proxmox-border rounded-xl p-5 w-full max-w-xl max-h-[90vh] overflow-y-auto space-y-4">
                        <h3 id="central-image-dialog-title" className="font-semibold">{importing ? t('centralAddImage') : `${t('centralCreateVM')}: ${selected.name}`}</h3>
                        {errorBox}
                        <fieldset disabled={busy || !canAct} className="space-y-3">
                            {importing ? <>
                                {field(t('name'), <input autoFocus required maxLength={128} value={importForm.name} onChange={e => setImportForm(f => ({ ...f, name: e.target.value }))} className={inputClass} />)}
                                <div className="grid grid-cols-2 gap-3">
                                    {field(t('centralImageType'), <select value={importForm.kind} onChange={e => { setFile(null); setImportForm(f => ({ ...f, kind: e.target.value })); }} className={inputClass}><option value="iso">{t('centralISO')}</option><option value="cloud">{t('centralCloudImage')}</option></select>)}
                                    {field(t('centralSource'), <select value={importForm.mode} onChange={e => setImportForm(f => ({ ...f, mode: e.target.value }))} className={inputClass}><option value="upload">{t('upload')}</option><option value="url">URL</option></select>)}
                                </div>
                                {importForm.mode === 'upload' ? field(t('centralFile'), <input key={importForm.kind} required type="file" accept={importForm.kind === 'iso' ? '.iso' : '.img,.qcow2'} onChange={e => setFile(e.target.files[0] || null)} className={inputClass} />)
                                    : field(t('centralPublicURL'), <input type="url" required value={importForm.source_url} onChange={e => setImportForm(f => ({ ...f, source_url: e.target.value }))} className={inputClass} />)}
                                {field(t('centralChecksum'), <input pattern="[a-fA-F0-9]{64}" maxLength={64} value={importForm.sha256} onChange={e => setImportForm(f => ({ ...f, sha256: e.target.value }))} className={inputClass} />)}
                                {importForm.kind === 'cloud' && field(t('centralCloudUser'), <input required value={importForm.default_user} onChange={e => setImportForm(f => ({ ...f, default_user: e.target.value }))} className={inputClass} />)}
                                <p className="text-xs text-gray-400">{t('centralImportHint')}</p>
                            </> : <>
                                {field(t('centralConnection'), connectionSelect)}
                                {field(t('node'), <select required value={form.node || ''} onChange={e => change('node', e.target.value)} className={inputClass}><option value="">{t('centralSelectNode')}</option>{nodes.map(node => <option key={node} value={node}>{node}</option>)}</select>)}
                                {targetsLoading && <p className="text-xs text-gray-400">{t('loading')}</p>}
                                {field(t('name'), <input autoFocus required pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,62}" value={form.name || ''} onChange={e => change('name', e.target.value)} className={inputClass} />)}
                                <div className="grid grid-cols-3 gap-3">
                                    {field(t('cores'), <input type="number" min={1} max={256} required value={form.cores} onChange={e => change('cores', e.target.value)} className={inputClass} />)}
                                    {field('RAM (MiB)', <input type="number" min={128} required value={form.memory} onChange={e => change('memory', e.target.value)} className={inputClass} />)}
                                    {field(t('centralDiskGB'), <input type="number" min={1} required value={form.disk_gb} onChange={e => change('disk_gb', e.target.value)} className={inputClass} />)}
                                </div>
                                <div className="grid grid-cols-2 gap-3">
                                    {field(t('storage'), storageSelect('storage', 'images'))}
                                    {field(t('bridge'), <select required value={form.bridge || ''} onChange={e => change('bridge', e.target.value)} className={inputClass}><option value="">{t('centralSelectBridge')}</option>{options.bridges.map(bridge => <option key={bridge} value={bridge}>{bridge}</option>)}</select>)}
                                </div>
                                {selected.kind === 'iso' ? <>
                                    {field(t('centralISOStorage'), storageSelect('iso_storage', 'iso'))}
                                    {field(t('osType'), <select value={form.ostype} onChange={e => change('ostype', e.target.value)} className={inputClass}><option value="l26">Linux</option><option value="win10">Windows 10 / Server</option><option value="other">{t('other')}</option></select>)}
                                    <p className="text-xs text-gray-400">{t('centralISOHint')}</p>
                                </> : <>
                                    {field(t('centralCloudUser'), <input required value={form.ciuser} onChange={e => change('ciuser', e.target.value)} className={inputClass} />)}
                                    {field(t('centralSSHKeys'), <textarea required rows={3} value={form.sshkeys} onChange={e => change('sshkeys', e.target.value)} placeholder="ssh-ed25519 AAAA…" className={`${inputClass} font-mono`} />)}
                                    <p className="text-xs text-gray-400">{t('centralCloudHint')}</p>
                                </>}
                                {field(`VMID (${t('optional')})`, <input type="number" min={100} max={999999999} placeholder={t('autoAssign')} value={form.vmid} onChange={e => change('vmid', e.target.value)} className={inputClass} />)}
                                <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.start} onChange={e => change('start', e.target.checked)} />{t('centralStartVM')}</label>
                            </>}
                        </fieldset>
                        <div className="flex justify-end gap-2">
                            <button type="button" disabled={busy} onClick={() => { setImporting(false); setSelected(null); }} className="px-3 py-2 text-sm text-gray-400">{t('cancel')}</button>
                            <button type="submit" className={buttonClass} disabled={busy || !canAct || (!importing && (targetsLoading || !form.node || !form.storage || !form.bridge || (selected.kind === 'iso' && !form.iso_storage)))}>{busy ? t('centralWorking') : t(importing ? 'centralAddImage' : 'centralCreateVM')}</button>
                        </div>
                    </form>
                </div>}
            </div>;
        }
