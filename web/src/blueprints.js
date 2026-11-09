        // LW Nov 2026 (#1220) - blueprints for Modern and Cloud.
        // The blueprints of Corporate Redesigned (cr_blueprints.js) drawn the way the Modern tabs are:
        // Automation > Blueprints & Templates shows them above the library cards, Cloud mounts the same
        // section in its .cloud-mounted frame (cloud), where the proxmox-* classes take the Cloud colours.
        // What a blueprint holds, the bodies it sends and the reads of the dialogs are the redesign's
        // (the crBp* helpers and crBpUseEditor / crBpUseDeploy / crBpUseProgress), so both looks follow
        // one set of rules. The section reads the blueprints and the recent deploys of this cluster once;
        // the library images, nodes, storages, bridges and templates when a dialog asks for them, and
        // the recent deploys again every BP_RECENT_POLL while one of them runs.
        // bp-fg and bp-muted (index.html.original) are the text colours of the palette: the light one of
        // Modern and Cloud reads as well as the dark ones.

        const BP_RECENT_POLL = 4000;
        const BP_RECENT_MAX = 50;
        const BP_STATE_TONE = { queued: 'neutral', running: 'info', completed: 'success', failed: 'error' };
        const BP_TONE = {
            neutral: 'bg-gray-500/20 text-gray-400', info: 'bg-blue-500/20 text-blue-400', success: 'bg-green-500/20 text-green-400',
            warning: 'bg-yellow-500/20 text-yellow-400', error: 'bg-red-500/20 text-red-400', template: 'bg-purple-500/20 text-purple-400',
        };
        const BP_NOTE = {
            info: ['bg-blue-500/10 border-blue-500/30', 'text-blue-400', 'Info'],
            warning: ['bg-yellow-500/10 border-yellow-500/30', 'text-yellow-400', 'AlertTriangle'],
            error: ['bg-red-500/10 border-red-500/30', 'text-red-400', 'AlertCircle'],
        };
        const BP_HINT = { error: 'text-red-400', warning: 'text-yellow-400', info: 'text-gray-500' };
        const BP_STEP_TONE = { done: 'success', current: 'info', failed: 'error', pending: 'neutral' };
        // the controls as the Modern tabs draw them
        const BP_INPUT = 'w-full px-3 py-1.5 bg-proxmox-dark border border-proxmox-border rounded text-sm bp-fg disabled:opacity-50';
        const BP_BTN = 'px-3 py-1.5 bg-proxmox-card border border-proxmox-border rounded-lg text-sm bp-fg hover:bg-proxmox-hover flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed';
        const BP_BTN_GO = 'px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 rounded-lg text-sm text-white flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed';
        const BP_BTN_ROW = 'px-2 py-1 border border-proxmox-border rounded text-xs bp-fg hover:bg-proxmox-hover flex items-center gap-1 disabled:opacity-50 disabled:cursor-not-allowed';
        const BP_BTN_ICON = 'p-1.5 rounded bp-muted hover:bg-proxmox-hover disabled:opacity-50 disabled:cursor-not-allowed';
        // the field grids: as many columns of at least min as there is room for (the static Tailwind build has
        // few responsive grid classes), a wide field over the whole row
        const bpGrid = (min) => ({ display: 'grid', gap: '0.75rem', gridTemplateColumns: `repeat(auto-fit, minmax(min(100%, ${min}), 1fr))` });
        const BP_WIDE = { gridColumn: '1 / -1' };

        function BpBadge({ tone = 'neutral', title, children, ...rest }) {
            return (
                <span className={`inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded whitespace-nowrap ${BP_TONE[tone] || BP_TONE.neutral}`}
                    title={title} {...rest}>{children}</span>
            );
        }

        function BpNote({ tone = 'info', id, children }) {
            const [box, icon, glyph] = BP_NOTE[tone] || BP_NOTE.info;
            const Glyph = Icons[glyph];
            return (
                <div className={`border rounded-lg p-3 text-xs bp-fg flex items-start gap-2 ${box}`} data-bp-note={id} data-bp-tone={tone}>
                    <Glyph className={`w-4 h-4 flex-shrink-0 ${icon}`} />
                    <div className="min-w-0 flex-1">{children}</div>
                </div>
            );
        }

        function BpState({ state }) {
            const { t } = useTranslation();
            return <BpBadge tone={BP_STATE_TONE[state] || 'neutral'} data-bp-state={state}>{t(CR_BP_STATE_WORD[state] || 'crBpStQueued')}</BpBadge>;
        }

        // one input with its label, and under it the error of the check or of the server, else its hint
        function BpField({ id, label, hint, tone, error, wide, children }) {
            const text = error || hint;
            const kind = error ? 'error' : tone || 'info';
            return (
                <div className="min-w-0" style={wide ? BP_WIDE : undefined} data-bp-field={id}>
                    <label htmlFor={`bp-f-${id}`} className="text-xs bp-muted block mb-1">{label}</label>
                    {children}
                    {text && <p className={`text-[11px] mt-1 ${BP_HINT[kind]}`} data-bp-hint={kind}>{text}</p>}
                </div>
            );
        }

        function BpCheck({ checked, onChange, label, ...rest }) {
            return (
                <label className="flex items-center gap-2 text-sm bp-fg cursor-pointer">
                    <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} {...rest} />
                    <span>{label}</span>
                </label>
            );
        }

        // two or more buttons of which one is picked (the source of a blueprint, the scope of the deploys)
        function BpSeg({ label, value, options, onPick, attr }) {
            return (
                <div className="inline-flex rounded-lg border border-proxmox-border overflow-hidden" role="group" aria-label={label}>
                    {options.map(([v, text]) => (
                        <button key={v} type="button" aria-pressed={value === v} onClick={() => onPick(v)} {...{ [attr]: v }}
                            className={`px-3 py-1.5 text-sm ${value === v ? 'bg-proxmox-orange text-white' : 'bp-fg hover:bg-proxmox-hover'}`}>
                            {text}
                        </button>
                    ))}
                </div>
            );
        }

        function BpGroup({ id, title, children }) {
            return (
                <section className="space-y-3" data-bp-group={id}>
                    <h4 className="text-xs font-semibold uppercase tracking-wider bp-muted border-b border-proxmox-border pb-1">{title}</h4>
                    {children}
                </section>
            );
        }

        // A Modern dialog: the title on top, the body scrolls, the buttons stay at the bottom. Escape and
        // a click beside it close it, not while it sends (busy); a press that started inside and ended
        // outside (selecting the text of a field) is no click beside it
        function BpModal({ id, title, sub, icon, wide, busy, onClose, footer, children }) {
            const { t } = useTranslation();
            const downOutside = useRef(false);
            const Glyph = icon || Icons.Template;
            useEffect(() => {
                const key = (e) => { if (e.key === 'Escape' && !busy) onClose(); };
                window.addEventListener('keydown', key);
                return () => window.removeEventListener('keydown', key);
            }, [busy, onClose]);
            return (
                <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" data-bp-modal={id}
                    onMouseDown={e => { downOutside.current = e.target === e.currentTarget; }}
                    onClick={e => { if (downOutside.current && e.target === e.currentTarget && !busy) onClose(); }}>
                    <div className={`bg-proxmox-card border border-proxmox-border rounded-xl shadow-2xl w-full ${wide ? 'max-w-4xl' : 'max-w-2xl'} max-h-[90vh] flex flex-col`}
                        role="dialog" aria-modal="true" aria-labelledby={`bp-${id}-title`}>
                        <div className="flex items-start justify-between gap-3 px-5 pt-4 pb-3 border-b border-proxmox-border">
                            <div className="min-w-0">
                                <h3 id={`bp-${id}-title`} className="text-base font-semibold bp-fg flex items-center gap-2">
                                    <Glyph className="w-4 h-4 text-proxmox-orange flex-shrink-0" />
                                    <span className="truncate">{title}</span>
                                </h3>
                                {sub && <p className="text-xs text-gray-500 mt-0.5">{sub}</p>}
                            </div>
                            <button type="button" className={BP_BTN_ICON} onClick={onClose} disabled={busy} aria-label={t('close')} title={t('close')} data-bp-modal-close={id}>
                                <Icons.X className="w-4 h-4" />
                            </button>
                        </div>
                        <div className="overflow-y-auto px-5 py-4 flex-1 space-y-4" data-bp-modal-body={id}>{children}</div>
                        <div className="flex justify-end flex-wrap gap-2 px-5 py-3 border-t border-proxmox-border">{footer}</div>
                    </div>
                </div>
            );
        }

        // --- the editor ----------------------------------------------------------------------------

        // New and Edit. bridges: names the bridge fields suggest (the network of one node of this cluster)
        function BpEditor({ bp, templateId, authFetch, bridges, onCancel, onSaved }) {
            const { t } = useTranslation();
            const { form, setForm, set, setNic, cat, busy, server, failed, tplSrc, win, err, odd, picked, save, general, diskHolder } =
                crBpUseEditor({ bp, templateId, authFetch, t, onSaved });
            const box = useRef(null);
            // a save that did not go through: the first error it left, on top or at a field, into view
            useEffect(() => {
                if (!failed || !box.current) return;
                const first = box.current.querySelector('[data-bp-note="save"], [data-bp-hint="error"]');
                if (first && first.scrollIntoView) first.scrollIntoView({ block: 'nearest' });
            }, [failed]);
            const input = (k, extra = {}) => (
                <input id={`bp-f-${k}`} className={BP_INPUT} value={form[k]} spellCheck={false} onChange={e => set(k, e.target.value)} data-bp-input={k} {...extra} />
            );
            return (
                <BpModal id="editor" wide busy={busy} onClose={onCancel}
                    title={bp ? crFill(t('crBpEditorEdit'), { name: bp.name }) : t('crBpEditorNew')}
                    footer={(
                        <>
                            <button type="button" className={BP_BTN} onClick={onCancel} disabled={busy} data-bp-editor-cancel="">{t('cancel')}</button>
                            <button type="button" className={BP_BTN_GO} onClick={save} disabled={busy} data-bp-editor-save="">
                                {busy ? <Icons.RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Icons.Save className="w-3.5 h-3.5" />}
                                {busy ? t('crNcSaving') : t('save')}
                            </button>
                        </>
                    )}>
                    <div className="space-y-5" ref={box} data-bp-editor={bp ? bp.id : 'new'} data-bp-src={form.source_kind} data-bp-os={tplSrc ? form.os : 'linux'}>
                        {general && <BpNote tone="error" id="save">{server.msg}</BpNote>}
                        <div className="space-y-1.5">
                            <span className="text-xs bp-muted block">{t('crBpFSource')}</span>
                            <BpSeg label={t('crBpFSource')} value={form.source_kind} onPick={v => set('source_kind', v)} attr="data-bp-source"
                                options={CR_BP_SOURCES.map(s => [s, t(CR_BP_SOURCE_WORD[s])])} />
                            <p className="text-xs text-gray-500">{t(tplSrc ? 'crBpSrcTemplateHint' : 'crBpSrcLibraryHint')}</p>
                        </div>
                        <div style={bpGrid('13rem')}>
                            <BpField id="name" label={t('crBpFName')} error={err('name')}>{input('name', { maxLength: 64, spellCheck: undefined })}</BpField>
                            {tplSrc ? (
                                <BpField id="os" label={t('crBpFOs')} error={err('os')} hint={t('crBpFOsHint')}>
                                    <select id="bp-f-os" className={BP_INPUT} value={form.os} onChange={e => set('os', e.target.value)} data-bp-input="os">
                                        {CR_BP_OS.map(o => <option key={o} value={o}>{t(CR_BP_OS_WORD[o])}</option>)}
                                    </select>
                                </BpField>
                            ) : (
                                <BpField id="template_id" label={t('crBpFImage')} error={err('template_id')}
                                    hint={cat.state === 'error' ? crFill(t('crBpCatalogFailed'), { reason: cat.why }) : t('crBpFImageHint')}
                                    tone={cat.state === 'error' ? 'warning' : undefined}>
                                    <select id="bp-f-template_id" className={BP_INPUT} value={form.template_id} onChange={e => set('template_id', e.target.value)}
                                        disabled={cat.state === 'loading' || cat.state === 'idle'} data-bp-input="template_id">
                                        <option value="">{cat.state === 'ok' || cat.state === 'error' ? t('crBpFImagePick') : t('crNcReading')}</option>
                                        {form.template_id && !picked && cat.state !== 'loading' && (
                                            <option value={form.template_id}>{(bp && bp.template_name) || form.template_id}</option>
                                        )}
                                        {cat.rows.map(r => <option key={r.id} value={r.id}>{r.name}{r.custom ? ` (${t('crBpCustom')})` : ''}</option>)}
                                    </select>
                                </BpField>
                            )}
                            <BpField id="tags" label={t('crBpFTags')} error={err('tags')} hint={t('crBpFTagsHint')}>{input('tags')}</BpField>
                            <BpField id="description" label={t('crBpFDesc')} wide error={err('description')}>
                                {input('description', { maxLength: 500, spellCheck: undefined })}
                            </BpField>
                        </div>

                        <BpGroup id="hw" title={t('crBpGroupHw')}>
                            <div style={bpGrid('9rem')}>
                                <BpField id="cores" label={t('crBpFCores')} error={err('cores')}>{input('cores', { inputMode: 'numeric' })}</BpField>
                                <BpField id="memory" label={t('crBpFMemory')} error={err('memory')}>
                                    <div className="flex gap-2">
                                        {input('memory', { inputMode: 'decimal' })}
                                        <select className={BP_INPUT} style={{ width: 'auto' }} value={form.memUnit} onChange={e => set('memUnit', e.target.value)} aria-label={t('crBpMemUnit')} data-bp-input="memUnit">
                                            <option value="GB">GB</option>
                                            <option value="MB">MB</option>
                                        </select>
                                    </div>
                                </BpField>
                                <BpField id="disk_gb" label={t('crBpFDisk')} error={err('disk_gb')} hint={t('crBpFDiskHint')}>
                                    {input('disk_gb', { inputMode: 'numeric', placeholder: diskHolder })}
                                </BpField>
                                <BpField id="cpu" label={t('crBpFCpu')} error={err('cpu')}
                                    hint={tplSrc ? t('crBpFCpuHintTpl') : picked && picked.cpu ? crFill(t('crBpFCpuHintImage'), { cpu: picked.cpu }) : t('crBpFCpuHint')}>
                                    {input('cpu', { placeholder: 'x86-64-v2-AES', className: `${BP_INPUT} font-mono` })}
                                </BpField>
                            </div>
                        </BpGroup>

                        <BpGroup id="net" title={t('crBpGroupNet')}>
                            {err('nics') && <p className="text-[11px] text-red-400" data-bp-hint="error">{err('nics')}</p>}
                            {tplSrc && <BpCheck checked={form.keepNet} onChange={v => set('keepNet', v)} label={t('crBpKeepNet')} data-bp-input="keepNet" />}
                            {tplSrc && form.keepNet ? <p className="text-xs text-gray-500" data-bp-keepnet="">{t('crBpKeepNetHint')}</p> : (
                                <>
                                    {bridges.length > 0 && <datalist id="bp-bridges">{bridges.map(b => <option key={b} value={b} />)}</datalist>}
                                    <ul className="space-y-2" aria-label={t('crBpGroupNet')}>
                                        {form.nics.map((n, i) => (
                                            <li key={i} className="grid gap-2 items-start bg-proxmox-dark border border-proxmox-border rounded-lg p-2" data-bp-nic={i}
                                                style={{ gridTemplateColumns: '2.75rem minmax(0, 1.3fr) minmax(0, 0.8fr) minmax(0, 1fr) auto 2rem' }}>
                                                <span className="font-mono text-xs bp-muted" style={{ paddingTop: 28 }}>{`net${i}`}</span>
                                                <BpField id={`nic${i}-bridge`} label={t('crBpFBridge')} error={err(`nic${i}-bridge`)}>
                                                    <input id={`bp-f-nic${i}-bridge`} className={`${BP_INPUT} font-mono`} value={n.bridge} spellCheck={false}
                                                        list={bridges.length ? 'bp-bridges' : undefined} onChange={e => setNic(i, 'bridge', e.target.value)} data-bp-nic-bridge={i} />
                                                </BpField>
                                                <BpField id={`nic${i}-vlan`} label={t('crBpFVlan')} error={err(`nic${i}-vlan`)}>
                                                    <input id={`bp-f-nic${i}-vlan`} className={BP_INPUT} inputMode="numeric" value={n.vlan} placeholder={t('crBpVlanNone')}
                                                        onChange={e => setNic(i, 'vlan', e.target.value)} data-bp-nic-vlan={i} />
                                                </BpField>
                                                <BpField id={`nic${i}-model`} label={t('crBpFModel')}>
                                                    <select id={`bp-f-nic${i}-model`} className={BP_INPUT} value={n.model} onChange={e => setNic(i, 'model', e.target.value)} data-bp-nic-model={i}>
                                                        {CR_BP_MODELS.map(m => <option key={m} value={m}>{m}</option>)}
                                                    </select>
                                                </BpField>
                                                <div style={{ paddingTop: 26 }}><BpCheck checked={n.firewall} onChange={v => setNic(i, 'firewall', v)} label={t('crBpFFirewall')} data-bp-nic-fw={i} /></div>
                                                <div style={{ paddingTop: 22 }}>
                                                    {form.nics.length > 1 && (
                                                        <button type="button" className={`${BP_BTN_ICON} hover:text-red-400`} data-bp-nic-remove={i}
                                                            onClick={() => setForm(f => ({ ...f, nics: f.nics.filter((_, j) => j !== i) }))}
                                                            title={crFill(t('crBpRemoveNic'), { n: `net${i}` })} aria-label={crFill(t('crBpRemoveNic'), { n: `net${i}` })}>
                                                            <Icons.X className="w-4 h-4" />
                                                        </button>
                                                    )}
                                                </div>
                                            </li>
                                        ))}
                                    </ul>
                                    {form.nics.length < CR_BP_MAX_NICS && (
                                        <button type="button" className={BP_BTN_ROW} onClick={() => setForm(f => ({ ...f, nics: [...f.nics, crBpNic()] }))} data-bp-nic-add="">
                                            <Icons.Plus className="w-3 h-3" />{t('crBpAddNic')}
                                        </button>
                                    )}
                                </>
                            )}
                        </BpGroup>

                        <BpGroup id="ci" title={t('crBpGroupCi')}>
                            {win && <BpNote tone="info" id="win"><span data-bp-win-note="">{t('crBpWinNote')}</span></BpNote>}
                            <div style={bpGrid('10rem')}>
                                {!win && (
                                    <BpField id="ciuser" label={t('crBpFUser')} error={err('ciuser')}
                                        hint={tplSrc ? t('crBpFUserHintTpl') : picked && picked.default_user ? crFill(t('crBpFUserHintImage'), { user: picked.default_user }) : t('crBpFUserHint')}>
                                        {input('ciuser', { autoComplete: 'off' })}
                                    </BpField>
                                )}
                                <BpField id="ip_mode" label={t('crBpFIpMode')} error={err('ip_mode')} hint={form.ip_mode === 'static' ? t('crBpIpStaticHint') : ''}>
                                    <select id="bp-f-ip_mode" className={BP_INPUT} value={form.ip_mode} onChange={e => set('ip_mode', e.target.value)} data-bp-input="ip_mode">
                                        {CR_BP_IP_MODES.map(m => <option key={m} value={m}>{t(CR_BP_IP_WORD[m])}</option>)}
                                    </select>
                                </BpField>
                                <BpField id="nameserver" label={t('crBpFDns')} error={err('nameserver')} hint={t('crBpFDnsHint')}>
                                    {input('nameserver', { className: `${BP_INPUT} font-mono` })}
                                </BpField>
                                {!win && <BpField id="searchdomain" label={t('crBpFSearch')} error={err('searchdomain')}>{input('searchdomain')}</BpField>}
                                {!win && (
                                    <BpField id="sshkeys" label={t('crBpFKeys')} wide error={err('sshkeys')}
                                        hint={odd.length ? crFill(t('crBpKeysOdd'), { n: odd.join(', ') }) : `${t('crBpFKeysHint')} ${t('crBpNoPassword')}`}
                                        tone={odd.length ? 'warning' : undefined}>
                                        <textarea id="bp-f-sshkeys" className={`${BP_INPUT} font-mono text-xs`} rows={3} value={form.sshkeys} spellCheck={false}
                                            placeholder="ssh-ed25519 AAAA... user@host" onChange={e => set('sshkeys', e.target.value)} data-bp-input="sshkeys" />
                                    </BpField>
                                )}
                            </div>
                        </BpGroup>

                        <BpGroup id="opts" title={t('crBpGroupDeploy')}>
                            <div className="flex flex-wrap gap-x-6 gap-y-1">
                                <BpCheck checked={form.start} onChange={v => set('start', v)} label={t('crBpFStart')} data-bp-input="start" />
                                {!win && <BpCheck checked={form.ciupgrade} onChange={v => set('ciupgrade', v)} label={t('crBpFUpgrade')} data-bp-input="ciupgrade" />}
                            </div>
                        </BpGroup>
                    </div>
                </BpModal>
            );
        }

        // --- the deploy ----------------------------------------------------------------------------

        // what the server says of a template of the blueprint's image on the picked node
        function BpTemplateHint({ tpl }) {
            const { t } = useTranslation();
            if (!tpl || tpl.state === 'idle') return null;
            if (tpl.state === 'loading') return <p className="text-xs text-gray-500" data-bp-tpl="loading">{t('crBpTplReading')}</p>;
            if (tpl.state === 'error') return <BpNote tone="warning" id="tpl">{crFill(t('crBpTplFailed'), { reason: tpl.why })}</BpNote>;
            const x = tpl.body && tpl.body.template;
            if (x && !tpl.body.build_needed) {
                return (
                    <BpNote tone="info" id="tpl">
                        <span data-bp-tpl="existing" data-bp-tpl-vmid={x.vmid}>
                            {crFill(t(x.shared ? 'crBpTplShared' : 'crBpTplUses'), { vmid: x.vmid, node: x.node, storage: x.storage || '' })}
                        </span>
                    </BpNote>
                );
            }
            return <BpNote tone="info" id="tpl"><span data-bp-tpl="build">{t('crBpTplBuild')}</span></BpNote>;
        }

        function BpProgress({ dep, onRow }) {
            const { t } = useTranslation();
            const { row, fail, status, at, steps, pct, log } = crBpUseProgress(dep, onRow, t);
            const bar = status === 'failed' ? 'bg-red-500' : status === 'completed' ? 'bg-green-500' : 'bg-blue-500';
            return (
                <div className="space-y-3" data-bp-progress={dep.id} data-bp-status={status}>
                    <div className="flex items-center gap-2 flex-wrap">
                        <BpState state={status} />
                        <span className="font-mono text-sm bp-fg">{crFill(t('crBpGuestLine'), { name: dep.name, vmid: dep.vmid })}</span>
                        <span className="text-xs text-gray-500 ml-auto">{`${Math.round(pct)}%`}</span>
                    </div>
                    <div className="h-2 bg-proxmox-dark border border-proxmox-border rounded-full overflow-hidden" role="progressbar"
                        aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} aria-label={t('crBpProgress')}>
                        <div className={`h-full rounded-full ${bar}`} style={{ width: `${pct}%` }} />
                    </div>
                    <ol className="flex flex-wrap gap-1.5" aria-label={t('crBpProgress')}>
                        {steps.map(s => {
                            const i = CR_BP_STEPS.indexOf(s);
                            const st = status === 'completed' || i < at ? 'done' : i === at ? (status === 'failed' ? 'failed' : 'current') : 'pending';
                            return (
                                <li key={s} data-bp-step={s} data-state={st}>
                                    <BpBadge tone={BP_STEP_TONE[st]}>
                                        {st === 'done' && <Icons.Check className="w-3 h-3" />}
                                        {st === 'failed' && <Icons.X className="w-3 h-3" />}
                                        {t(CR_BP_STEP_WORD[s])}
                                    </BpBadge>
                                </li>
                            );
                        })}
                    </ol>
                    {dep.build_needed && <p className="text-xs text-gray-500">{t('crBpProgBuild')}</p>}
                    {dep.warnings && dep.warnings.length > 0 && (
                        <BpNote tone="warning" id="warnings">
                            <span>{t('crBpWarnTitle')}</span>
                            <ul className="list-disc pl-4 mt-1 space-y-0.5" data-bp-warnings="">{dep.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
                        </BpNote>
                    )}
                    {dep.quota_warning && <BpNote tone="warning" id="quota">{crFill(t('crBpQuotaWarn'), { msg: String(dep.quota_warning) })}</BpNote>}
                    {fail && <BpNote tone="warning" id="prog-read">{crFill(t('crBpProgReadFailed'), { reason: fail })}</BpNote>}
                    {row && row.status === 'failed' && <BpNote tone="error" id="failed"><span data-bp-failed="">{row.error || t('crBpStFailed')}</span></BpNote>}
                    {log.length > 0 && (
                        <details open={status === 'failed'}>
                            <summary className="text-xs bp-muted cursor-pointer">{t('crBpLog')}</summary>
                            <pre className="mt-1 p-2 bg-proxmox-darker border border-proxmox-border rounded text-[11px] font-mono bp-fg whitespace-pre-wrap overflow-auto max-h-48"
                                data-bp-log="">{log.join('\n')}</pre>
                        </details>
                    )}
                    {crBpLive(status) && <p className="text-xs text-gray-500">{t('crBpProgClosedNote')}</p>}
                </div>
            );
        }

        // where to, then the progress of the deploy it started
        function BpDeploy({ bp, clusters, clusterId, authFetch, canWrite, nav, onClose, onStarted }) {
            const { t } = useTranslation();
            const { tplSrc, win, targets, form, set, setVmidTyped, nodes, stores, tpl, vnets, busy, server, dep, setRow, tplRows, away,
                    storeRows, missing, err, longName, go, tplHint, access, cl, done, guest, general } = crBpUseDeploy({ bp, clusters, clusterId, authFetch, t, onStarted });
            const [showPw, setShowPw] = useState(false);
            const openGuest = () => {
                const g = guest();
                onClose();
                nav.openGuest(dep.cid, g);
            };
            const footer = dep ? (
                <>
                    {done && nav && typeof nav.openGuest === 'function' && (
                        <button type="button" className={BP_BTN_GO} onClick={openGuest} data-bp-open-guest={dep.vmid}>
                            <Icons.ExternalLink className="w-3.5 h-3.5" />{crFill(t('crBpOpenGuest'), { vmid: dep.vmid })}
                        </button>
                    )}
                    <button type="button" className={BP_BTN} onClick={onClose} data-bp-deploy-close="">{t('close')}</button>
                </>
            ) : (
                <>
                    <button type="button" className={BP_BTN} onClick={onClose} disabled={busy} data-bp-deploy-cancel="">{t('cancel')}</button>
                    <button type="button" className={BP_BTN_GO} onClick={go} disabled={busy || !canWrite || !targets.length} data-bp-deploy-go="">
                        {busy ? <Icons.RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Icons.Play className="w-3.5 h-3.5" />}
                        {busy ? t('crBpStarting') : t('crBpDeployGo')}
                    </button>
                </>
            );
            const storeHint = stores.state === 'error' ? crFill(t('crBpStoragesFailed'), { reason: stores.why })
                : stores.state === 'ok' && !stores.rows.length ? t('crBpNoStorages')
                : stores.state === 'ok' && away ? crFill(t(storeRows.length ? 'crBpStorageSharedOnly' : 'crBpStorageNoShared'), { node: away }) : '';
            return (
                <BpModal id="deploy" busy={busy} onClose={onClose} footer={footer} icon={dep ? Icons.Activity : Icons.Play}
                    title={crFill(t(dep ? 'crBpProgTitle' : 'crBpDeployTitle'), { name: bp.name })}
                    sub={dep && cl ? `${cl.display_name || cl.name} · ${dep.node}` : undefined}>
                    {dep ? <BpProgress dep={dep} onRow={setRow} /> : (
                        <div className="space-y-4" data-bp-deploy-form={bp.id} data-bp-src={tplSrc ? 'template' : 'library'}>
                            {general && <BpNote tone="error" id="deploy">{server.msg}</BpNote>}
                            {!targets.length ? <BpNote tone="warning" id="noclusters">{t('crBpNoClusters')}</BpNote> : (
                                <div style={bpGrid('15rem')}>
                                    <BpField id="cluster_id" label={t('crBpFCluster')} error={err('cluster_id')}>
                                        <select id="bp-f-cluster_id" className={BP_INPUT} value={form.cluster_id} onChange={e => set('cluster_id', e.target.value)} data-bp-dep="cluster_id">
                                            {targets.map(c => <option key={c.id} value={c.id}>{c.display_name || c.name}</option>)}
                                        </select>
                                    </BpField>
                                    <BpField id="node" label={t('crBpFNode')} error={err('node')}
                                        hint={nodes.state === 'error' ? crFill(t('crBpNodesFailed'), { reason: nodes.why }) : nodes.state === 'ok' && !nodes.rows.length ? t('crBpNoNodes') : ''}
                                        tone={nodes.state === 'error' || (nodes.state === 'ok' && !nodes.rows.length) ? 'warning' : undefined}>
                                        <select id="bp-f-node" className={BP_INPUT} value={form.node} onChange={e => set('node', e.target.value)}
                                            disabled={nodes.state !== 'ok' || !nodes.rows.length} data-bp-dep="node">
                                            {nodes.state === 'loading' && <option value="">{t('crNcReading')}</option>}
                                            {nodes.rows.map(n => <option key={n} value={n}>{n}</option>)}
                                        </select>
                                    </BpField>
                                    <BpField id="storage" label={t('crBpFStorage')} error={err('storage')} hint={storeHint}
                                        tone={stores.state === 'error' || (stores.state === 'ok' && (!stores.rows.length || (away && !storeRows.length))) ? 'warning' : undefined}>
                                        <select id="bp-f-storage" className={BP_INPUT} value={form.storage} onChange={e => set('storage', e.target.value)}
                                            disabled={stores.state !== 'ok' || !storeRows.length} data-bp-dep="storage">
                                            {stores.state === 'loading' && <option value="">{t('crNcReading')}</option>}
                                            {storeRows.map(s => <option key={s} value={s}>{s}</option>)}
                                        </select>
                                    </BpField>
                                    <BpField id="vmid" label={t('crBpFVmid')} error={err('vmid')} hint={t('crBpFVmidHint')}>
                                        <input id="bp-f-vmid" className={BP_INPUT} inputMode="numeric" value={form.vmid}
                                            onChange={e => { setVmidTyped(true); set('vmid', e.target.value); }} data-bp-dep="vmid" />
                                    </BpField>
                                    {tplSrc && (
                                        <BpField id="template_vmid" label={t('crBpFTemplate')} wide error={err('template_vmid')} hint={tplHint()}
                                            tone={tpl.state === 'error' || (tpl.state === 'ok' && !tplRows.length) ? 'warning' : undefined}>
                                            <select id="bp-f-template_vmid" className={BP_INPUT} value={form.template_vmid} onChange={e => set('template_vmid', e.target.value)}
                                                disabled={tpl.state !== 'ok' || !tplRows.length} data-bp-dep="template_vmid">
                                                <option value="">{tpl.state === 'loading' ? t('crNcReading') : t('crBpFTemplatePick')}</option>
                                                {tplRows.map(x => {
                                                    const why = crBpTplWhy(x, t);
                                                    return (
                                                        <option key={x.vmid} value={String(x.vmid)} disabled={!!why} data-bp-tpl-why={why || undefined}>
                                                            {`${x.name || 'VM'} (${x.vmid}) · ${x.node || ''} · ${x.ostype || ''}${why ? ` (${why})` : ''}`}
                                                        </option>
                                                    );
                                                })}
                                            </select>
                                        </BpField>
                                    )}
                                    <BpField id="vmname" label={t('crBpFVmName')} wide error={err('name')}
                                        hint={longName ? crFill(t('crBpWinNameLong'), { n: CR_BP_WIN_NAME }) : ''} tone={longName ? 'warning' : undefined}>
                                        <input id="bp-f-vmname" className={BP_INPUT} value={form.name} spellCheck={false} maxLength={63} onChange={e => set('name', e.target.value)} data-bp-dep="name" />
                                    </BpField>
                                    {bp.ip_mode === 'static' && (
                                        <>
                                            <BpField id="ip" label={t('crBpFIp')} error={err('ip')}>
                                                <input id="bp-f-ip" className={`${BP_INPUT} font-mono`} value={form.ip} spellCheck={false} placeholder="10.0.0.5/24" onChange={e => set('ip', e.target.value)} data-bp-dep="ip" />
                                            </BpField>
                                            <BpField id="gw" label={t('crBpFGw')} error={err('gw')}>
                                                <input id="bp-f-gw" className={`${BP_INPUT} font-mono`} value={form.gw} spellCheck={false} placeholder="10.0.0.1" onChange={e => set('gw', e.target.value)} data-bp-dep="gw" />
                                            </BpField>
                                        </>
                                    )}
                                    <BpField id="password" label={t(win ? 'crBpFPasswordWin' : 'crBpFPassword')} wide error={err('password')}
                                        hint={t(win ? 'crBpFPasswordHintWin' : 'crBpFPasswordHint')}>
                                        <div className="flex gap-2">
                                            <input id="bp-f-password" type={showPw ? 'text' : 'password'} className={BP_INPUT} value={form.password} autoComplete="new-password"
                                                spellCheck={false} required={win} onChange={e => set('password', e.target.value)} data-bp-dep="password" />
                                            <button type="button" className={`${BP_BTN} flex-shrink-0`} aria-pressed={showPw} title={t('crBpPwShow')} aria-label={t('crBpPwShow')}
                                                onClick={() => setShowPw(v => !v)} data-bp-pw-show="">
                                                <Icons.Eye className={`w-4 h-4 ${showPw ? 'text-proxmox-orange' : ''}`} />
                                            </button>
                                        </div>
                                    </BpField>
                                </div>
                            )}
                            {targets.length > 0 && <BpCheck checked={form.start} onChange={v => set('start', v)} label={t('crBpFStartNow')} data-bp-dep="start" />}
                            {!tplSrc && <BpTemplateHint tpl={tpl} />}
                            <p className="text-xs text-gray-500 bg-proxmox-dark border border-proxmox-border rounded-lg px-3 py-2" data-bp-summary="">
                                {crFill(t('crBpDeploySummary'), { hw: crBpHw(bp, t), net: crBpNet(bp, t), ip: t(CR_BP_IP_WORD[bp.ip_mode] || 'crBpIpDhcp') })}
                            </p>
                            {access && (
                                <BpNote tone="info" id="access">
                                    <span data-bp-access={bp.created_by || ''}>{access}</span>
                                </BpNote>
                            )}
                            {missing.length > 0 && (
                                <BpNote tone="warning" id="bridges">
                                    <span data-bp-bridge-missing={missing.join(' ')}>
                                        {crFill(t(vnets.state === 'ok' ? 'crBpBridgeMissing' : 'crBpBridgeMissingNoVnet'), { bridges: missing.join(', '), node: form.node })}
                                    </span>
                                </BpNote>
                            )}
                        </div>
                    )}
                </BpModal>
            );
        }

        // --- the recent deploys --------------------------------------------------------------------

        // The deploys of the blueprints, this cluster's or every cluster's (one read each, the scope a
        // button). Read when shown, on Refresh, after a deploy the section started (ran counts them)
        // and every BP_RECENT_POLL while one of the listed deploys is queued or running
        function BpRecent({ cid, clusters, authFetch, nav, ran }) {
            const { t } = useTranslation();
            const [scope, setScope] = useState('cluster');
            const [lists, setLists] = useState({ cluster: null, all: null });
            const seq = useRef(0);
            const byId = new Map((clusters || []).map(c => [c.id, c]));
            const read = (which) => {
                const my = ++seq.current;
                const url = which === 'all' ? `${API_URL}/blueprints/deployments`
                    : `${API_URL}/blueprints/deployments?cluster_id=${encodeURIComponent(cid)}`;
                setLists(l => ({ ...l, [which]: l[which] ? { ...l[which], busy: true } : { state: 'loading', rows: [], why: '' } }));
                crDriftRead(authFetch, url).then(r => {
                    if (my !== seq.current) return;
                    setLists(l => ({ ...l, [which]: r.state === 'ok'
                        ? { state: 'ok', rows: Array.isArray(r.body.deployments) ? r.body.deployments : [], why: '' }
                        : { state: 'error', rows: [], why: crDriftReadText(r, t) } }));
                });
            };
            useEffect(() => { read(scope); }, [scope, ran]);
            useEffect(() => () => { seq.current += 1; }, []);
            const list = lists[scope] || { state: 'loading', rows: [], why: '' };
            const live = list.rows.some(r => r && crBpLive(r.status));
            useEffect(() => {
                if (!live) return undefined;
                const timer = setTimeout(() => read(scope), BP_RECENT_POLL);
                return () => clearTimeout(timer);
            }, [live, list]);
            const inAll = scope === 'all';
            const rows = list.rows.filter(Boolean).slice().sort((a, b) => String(b.started_at || '').localeCompare(String(a.started_at || '')));
            const shown = rows.slice(0, BP_RECENT_MAX);
            const name = (id) => { const c = byId.get(id); return c ? c.display_name || c.name || c.id : id || ''; };
            const th = 'px-3 py-2 font-medium';
            const td = 'px-3 py-1.5';
            return (
                <div className="bg-proxmox-card border border-proxmox-border rounded-xl p-4 space-y-3" data-bp-recent={scope}>
                    <div className="flex items-start justify-between flex-wrap gap-2">
                        <div>
                            <h3 className="text-sm font-semibold bp-fg flex items-center gap-2"><Icons.Clock className="w-4 h-4 text-proxmox-orange" />{t('crImgRecentTitle')}</h3>
                            <p className="text-xs text-gray-500 mt-0.5">{t('bpRecentDesc')}</p>
                        </div>
                        <div className="flex items-center gap-2">
                            <BpSeg label={t('crImgScope')} value={scope} onPick={setScope} attr="data-bp-recent-scope"
                                options={[['cluster', t('crImgScopeHere')], ['all', t('crImgScopeAll')]]} />
                            <button type="button" className={BP_BTN} onClick={() => read(scope)} disabled={list.busy} data-bp-recent-refresh="">
                                <Icons.RefreshCw className={`w-3.5 h-3.5 ${list.busy ? 'animate-spin' : ''}`} />{t('refresh')}
                            </button>
                        </div>
                    </div>
                    {list.state === 'error' && <BpNote tone="warning" id="recent-error">{crFill(t('crImgRecentBpFailed'), { reason: list.why })}</BpNote>}
                    {list.state === 'loading' ? <p className="text-xs text-gray-500" data-bp-recent-loading="">{t('crNcReading')}</p>
                        : list.state === 'ok' && !rows.length ? <p className="text-xs text-gray-500" data-bp-recent-empty="">{t(inAll ? 'bpRecentNoneAll' : 'bpRecentNone')}</p>
                        : rows.length > 0 && (
                            <div className="overflow-x-auto">
                                <table className="w-full text-xs">
                                    <thead>
                                        <tr className="text-left bp-muted border-b border-proxmox-border">
                                            <th className={th}>{t('bpColBlueprint')}</th>
                                            <th className={th}>{t('crImgColGuest')}</th>
                                            {inAll && <th className={th}>{t('crImgColCluster')}</th>}
                                            <th className={th}>{t('crImgColNode')}</th>
                                            <th className={th}>{t('crImgColState')}</th>
                                            <th className={th}>{t('crImgColStarted')}</th>
                                            <th className={th}>{t('crImgColBy')}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {shown.map(r => {
                                            const label = r.name ? `${r.name} (${r.vmid})` : String(r.vmid ?? '');
                                            const pct = Number(r.progress);
                                            return (
                                                <tr key={r.id} className="border-b border-proxmox-border/50" data-bp-recent-row={r.id}>
                                                    <td className={`${td} bp-fg`}>{r.blueprint_name || r.blueprint_id || ''}</td>
                                                    <td className={td}>
                                                        {r.status === 'completed' && r.vmid && nav && typeof nav.openGuest === 'function' ? (
                                                            <button type="button" className="font-mono text-proxmox-orange hover:underline" data-bp-guest={r.vmid}
                                                                onClick={() => nav.openGuest(r.cluster_id || cid, { vmid: Number(r.vmid), node: r.node, type: 'qemu', name: r.name || '' })}>{label}</button>
                                                        ) : <span className="font-mono bp-fg">{label}</span>}
                                                    </td>
                                                    {inAll && <td className={`${td} bp-fg`} data-bp-recent-cluster={r.cluster_id}>{name(r.cluster_id)}</td>}
                                                    <td className={`${td} bp-fg`}>{r.node}</td>
                                                    <td className={td}>
                                                        <span className="flex items-center gap-1.5 min-w-0">
                                                            <BpState state={r.status} />
                                                            {r.status === 'running' && Number.isFinite(pct) && <span className="bp-muted">{`${Math.max(0, Math.min(100, Math.round(pct)))}%`}</span>}
                                                            {r.status === 'failed' && r.error && <span className="text-red-400 truncate" style={{ maxWidth: 260 }} title={r.error}>{r.error}</span>}
                                                        </span>
                                                    </td>
                                                    <td className={`${td} bp-muted whitespace-nowrap`} title={t('crDriftServerTime')}>{crDriftTime(String(r.started_at || ''))}</td>
                                                    <td className={`${td} bp-muted`}>{r.started_by}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    {rows.length > shown.length && <p className="text-xs text-gray-500">{crFill(t('crImgRecentNewest'), { max: shown.length, n: rows.length })}</p>}
                </div>
            );
        }

        // --- the section ---------------------------------------------------------------------------

        // canRead: the account holds vm.create (the routes ask for it); canWrite: it may use it here (not
        // on a standby). nav: openGuest(cid, guest) for the guest a deploy made, nodesOf(cid) for the
        // bridges the editor suggests (both optional). cloud: drawn inside the Cloud layout
        function BpSection({ cluster, clusters, authFetch, addToast, canRead, canWrite, nav, cloud }) {
            const { t } = useTranslation();
            const { haReadOnly } = useAuth();
            const { isCloud } = useLayout();
            const cid = cluster && cluster.id;
            const [list, setList] = useState({ state: 'loading', rows: [], why: '' });
            const [editor, setEditor] = useState(null);
            const [deploy, setDeploy] = useState(null);
            const [del, setDel] = useState(null);
            const [delBusy, setDelBusy] = useState(false);
            const [bridges, setBridges] = useState([]);
            const [ran, setRan] = useState(0);
            const write = canWrite && !haReadOnly;
            const why = !write ? t(haReadOnly ? 'crBpStandby' : 'crBpNeedsPerm') : undefined;
            const layout = (cloud === undefined ? isCloud : cloud) ? 'cloud' : 'modern';

            const loadList = async () => {
                if (!canRead) return;
                setList(l => ({ ...l, state: l.state === 'ok' ? 'ok' : 'loading', busy: true }));
                const read = await crDriftRead(authFetch, `${API_URL}/blueprints`);
                if (read.state === 'ok') setList({ state: 'ok', rows: Array.isArray(read.body.blueprints) ? read.body.blueprints : [], why: '' });
                else setList({ state: 'error', rows: [], why: crDriftReadText(read, t) });
            };
            useEffect(() => { loadList(); }, [canRead]);

            // the bridges of one online node of this cluster, once, for the NIC fields of the editor
            const openEditor = (bp) => {
                setEditor({ bp });
                if (bridges.length || !cid) return;
                const metrics = nav && typeof nav.nodesOf === 'function' ? nav.nodesOf(cid) : null;
                const node = metrics ? Object.keys(metrics).sort(crCompare).find(n => !metrics[n] || metrics[n].status !== 'offline') : null;
                if (!node) return;
                crDriftRead(authFetch, `${API_URL}/clusters/${encodeURIComponent(cid)}/nodes/${encodeURIComponent(node)}/network`).then(read => {
                    if (read.state === 'ok') setBridges(crBpBridges(read.body));
                });
            };
            const saved = (bp, isNew) => {
                setEditor(null);
                addToast(t(isNew ? 'crBpCreated' : 'crBpSaved'), 'success');
                loadList();
            };
            // a deploy of a template source may have remembered its template for the cluster
            const started = (bp) => {
                if (crBpIsTpl(bp)) loadList();
                setRan(n => n + 1);
            };
            const remove = async () => {
                if (!del) return;
                setDelBusy(true);
                const res = await crBpSend(authFetch, `${API_URL}/blueprints/${encodeURIComponent(del.id)}`, 'DELETE');
                setDelBusy(false);
                if (res.ok) {
                    setDel(null);
                    addToast(t('crBpDeleted'), 'success');
                    loadList();
                    return;
                }
                addToast(crBpSendText(res, t), 'error');
            };

            if (!canRead) {
                return (
                    <div className="space-y-2" data-bp="" data-bp-layout={layout}>
                        <h2 className="text-lg font-semibold bp-fg flex items-center gap-2"><Icons.Template className="w-5 h-5 text-proxmox-orange" />{t('crBpTitle')}</h2>
                        <BpNote tone="info" id="noperm"><span data-bp-noperm="">{t('crBpNoPerm')}</span></BpNote>
                    </div>
                );
            }
            const rows = list.rows.slice().sort((a, b) => crCompare(a.name || '', b.name || ''));
            const th = 'px-3 py-2 font-medium whitespace-nowrap';
            const td = 'px-3 py-2';
            return (
                <div className="space-y-4" data-bp="" data-bp-layout={layout}>
                    <div className="flex items-start justify-between flex-wrap gap-2">
                        <div className="min-w-0">
                            <h2 className="text-lg font-semibold bp-fg flex items-center gap-2 flex-wrap">
                                <Icons.Template className="w-5 h-5 text-proxmox-orange" />
                                {t('crBpTitle')}
                                {list.state === 'ok' && <BpBadge tone="neutral" data-bp-count={list.rows.length}>{list.rows.length}</BpBadge>}
                                <BpBadge tone="info" title={t('crBpAllClustersHint')} data-bp-scope="all"><Icons.Globe className="w-3 h-3" />{t('crBpAllClusters')}</BpBadge>
                            </h2>
                            <p className="text-xs text-gray-500 mt-0.5 max-w-3xl">{t('crBpDesc')}</p>
                        </div>
                        <div className="flex gap-2">
                            <button type="button" className={BP_BTN} onClick={loadList} disabled={list.busy} data-bp-refresh="">
                                <Icons.RefreshCw className="w-3.5 h-3.5" />{t('refresh')}
                            </button>
                            <button type="button" className={BP_BTN_GO} onClick={() => openEditor(null)} disabled={!write} title={why} data-bp-new="">
                                <Icons.Plus className="w-3.5 h-3.5" />{t('crBpNew')}
                            </button>
                        </div>
                    </div>
                    {haReadOnly && <BpNote tone="info" id="standby"><span data-bp-standby="">{t('crBpStandby')}</span></BpNote>}
                    {list.state === 'loading' ? <p className="text-xs text-gray-500" data-bp-loading="">{t('crNcReading')}</p>
                        : list.state === 'error' ? (
                            <BpNote tone="error" id="error">
                                <div className="flex items-center justify-between gap-2 flex-wrap" data-bp-error="">
                                    <span>{crFill(t('crBpReadFailed'), { reason: list.why })}</span>
                                    <button type="button" className={BP_BTN_ROW} onClick={loadList}>{t('retry')}</button>
                                </div>
                            </BpNote>
                        )
                        : !rows.length ? <BpNote tone="info" id="empty"><span data-bp-empty="">{t('crBpEmpty')}</span></BpNote>
                        : (
                            <div className="bg-proxmox-card border border-proxmox-border rounded-xl overflow-x-auto">
                                <table className="w-full text-sm" aria-label={t('crBpTitle')} data-bp-table="">
                                    <thead>
                                        <tr className="text-left text-xs bp-muted border-b border-proxmox-border">
                                            <th className={th}>{t('crBpColName')}</th>
                                            <th className={th}>{t('crBpColSource')}</th>
                                            <th className={th}>{t('crBpColHw')}</th>
                                            <th className={th}>{t('crBpColNet')}</th>
                                            <th className={th}><span className="sr-only">{t('crBpDeploy')}</span></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {rows.map(r => {
                                            const tplRow = crBpIsTpl(r);
                                            const here = tplRow ? crBpMapped(r, cid) : null;
                                            const tags = Array.isArray(r.tags) ? r.tags.filter(Boolean) : [];
                                            const gone = !tplRow && r.template_missing;
                                            return (
                                                <tr key={r.id} className="border-b border-proxmox-border/50 hover:bg-proxmox-hover" data-bp-row={r.id}>
                                                    {/* the tags and who saved it under the name: at 1280 px the row keeps its actions in view */}
                                                    <td className={td} style={{ minWidth: 160 }}>
                                                        <div className="font-medium bp-fg">{r.name}</div>
                                                        {r.description && <div className="text-xs text-gray-500 mt-0.5">{r.description}</div>}
                                                        <div className="flex flex-wrap items-center gap-1 mt-1">
                                                            {tags.map(x => <span key={x} className="text-[10px] px-1.5 py-0.5 bg-proxmox-dark border border-proxmox-border rounded bp-muted" data-bp-tag={x}>{x}</span>)}
                                                            {r.created_by && (
                                                                <span className="text-[11px] bp-muted flex items-center gap-1" title={t('crBpColBy')} data-bp-by={r.created_by}>
                                                                    <Icons.User className="w-3 h-3" />{r.created_by}
                                                                </span>
                                                            )}
                                                        </div>
                                                    </td>
                                                    <td className={td}>
                                                        {tplRow ? (
                                                            <div className="space-y-1" data-bp-source-cell="template" data-bp-os={crBpIsWin(r) ? 'windows' : 'linux'}>
                                                                <BpBadge tone="template" title={t('crBpSrcTemplateHint')}>{crBpSourceText(r, t)}</BpBadge>
                                                                {here && <div className="text-xs text-gray-500" data-bp-mapped={here}>{crFill(t('crBpSrcMappedHere'), { vmid: here })}</div>}
                                                            </div>
                                                        ) : gone ? (
                                                            <span data-bp-image="missing"><BpBadge tone="warning" title={t('crBpImageGoneHint')}><Icons.AlertTriangle className="w-3 h-3" />{t('crBpImageGone')}</BpBadge></span>
                                                        ) : <span className="bp-fg" data-bp-source-cell="library" data-bp-image={r.template_id}>{crBpSourceText(r, t)}</span>}
                                                    </td>
                                                    <td className={`${td} text-xs bp-muted whitespace-nowrap`} data-bp-hw={r.id}>{crBpHw(r, t)}</td>
                                                    <td className={`${td} text-xs`} style={{ maxWidth: 190 }}>
                                                        <span className="block truncate font-mono bp-muted" title={crBpNet(r, t)} data-bp-net={r.id}>{crBpNet(r, t)}</span>
                                                        <span className="block mt-0.5 bp-muted" data-bp-ip={r.ip_mode || 'dhcp'}>{`${t('crBpColIp')} ${t(CR_BP_IP_WORD[r.ip_mode] || 'crBpIpDhcp')}`}</span>
                                                    </td>
                                                    <td className={td}>
                                                        {/* Deploy last, so it stands in one column whether Edit and Delete are there or not */}
                                                        <div className="flex items-center justify-end gap-1">
                                                            {r.can_edit && (
                                                                <>
                                                                    <button type="button" className={BP_BTN_ICON} disabled={!write} title={why || t('edit')} aria-label={t('edit')}
                                                                        onClick={() => openEditor(r)} data-bp-edit={r.id}><Icons.Edit className="w-3.5 h-3.5" /></button>
                                                                    <button type="button" className={`${BP_BTN_ICON} hover:text-red-400`} disabled={!write}
                                                                        title={why || crFill(t('crBpDeleteTitle'), { name: r.name })} aria-label={crFill(t('crBpDeleteTitle'), { name: r.name })}
                                                                        onClick={() => setDel(r)} data-bp-delete={r.id}><Icons.Trash2 className="w-3.5 h-3.5" /></button>
                                                                </>
                                                            )}
                                                            <button type="button" className={BP_BTN_ROW} disabled={!write || gone} title={gone ? t('crBpImageGoneHint') : why}
                                                                onClick={() => setDeploy(r)} data-bp-deploy={r.id}>
                                                                <Icons.Play className="w-3 h-3 text-proxmox-orange" />{t('crBpDeploy')}
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    <BpRecent cid={cid} clusters={clusters} authFetch={authFetch} nav={nav} ran={ran} />
                    {editor && (
                        <BpEditor bp={editor.bp} templateId="" authFetch={authFetch} bridges={bridges} onCancel={() => setEditor(null)} onSaved={saved} />
                    )}
                    {deploy && (
                        <BpDeploy bp={deploy} clusters={clusters} clusterId={cid} authFetch={authFetch} canWrite={write} nav={nav}
                            onClose={() => setDeploy(null)} onStarted={() => started(deploy)} />
                    )}
                    {del && (
                        <BpModal id="delete" busy={delBusy} onClose={() => setDel(null)} icon={Icons.Trash2}
                            title={crFill(t('crBpDeleteTitle'), { name: del.name })}
                            footer={(
                                <>
                                    <button type="button" className={BP_BTN} onClick={() => setDel(null)} disabled={delBusy} data-bp-confirm-cancel="">{t('cancel')}</button>
                                    <button type="button" className="px-3 py-1.5 bg-red-600 hover:bg-red-700 rounded-lg text-sm text-white flex items-center gap-1.5 disabled:opacity-50"
                                        onClick={remove} disabled={delBusy} data-bp-confirm-go="">
                                        <Icons.Trash2 className="w-3.5 h-3.5" />{t('delete')}
                                    </button>
                                </>
                            )}>
                            <p className="text-sm bp-fg" data-bp-confirm="delete">{t('crBpDeleteText')}</p>
                        </BpModal>
                    )}
                </div>
            );
        }

        // a section that cannot be drawn says so, the rest of the tab stays
        class BpBoundary extends React.Component {
            constructor(props) {
                super(props);
                this.state = { error: null };
            }
            static getDerivedStateFromError(error) { return { error }; }
            componentDidCatch(error) { console.warn('[blueprints] the section could not be drawn:', error && error.message); }
            render() {
                if (!this.state.error) return this.props.children;
                return (
                    <BpNote tone="error" id="boundary">
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                            <span>{this.props.t('crBoundaryTitle')}</span>
                            <button type="button" className={BP_BTN_ROW} onClick={() => this.setState({ error: null })}>{this.props.t('retry')}</button>
                        </div>
                    </BpNote>
                );
            }
        }

        // The mount for Modern and Cloud: { cluster, clusters, authFetch, addToast, canRead, canWrite, nav, cloud }
        function Blueprints(props) {
            const { t } = useTranslation();
            return <BpBoundary t={t}><BpSection {...props} /></BpBoundary>;
        }
