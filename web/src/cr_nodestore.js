        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned: storage, repositories and Ceph of a node - LW Nov 2026
        // Configure > LVM, LVM-Thin and ZFS of a Proxmox VE node from the one disks read the view
        // already makes (disks, disks/lvm, disks/lvmthin, disks/zfs, kept by loadTabData with the
        // reason of a failed read), Repositories from the repos read and Ceph from its four reads.
        // Built from the section parts of cr_nodecfg.js. The pool detail is the shared
        // ZfsPoolDetail; a repository switch and apt update go through the handlers of
        // CorporateNodeDetailView with the classic requests. A value the node did not report says
        // so in a neutral style, never as a dash or as healthy.
        // ═══════════════════════════════════════════════════════════

        // a number PVE sent as a number or a numeric string, else null
        const crNvNum = (v) => {
            if (typeof v === 'number') return Number.isFinite(v) ? v : null;
            if (typeof v === 'string' && /^\s*-?\d+(\.\d+)?\s*$/.test(v)) return parseFloat(v);
            return null;
        };
        const crNvBytes = (v) => { const n = crNvNum(v); return n != null && n >= 0 ? formatBytes(n) : null; };
        // the share of two byte counts in percent; null when one is missing or the total is 0
        const crNvPct = (used, total) => {
            const u = crNvNum(used), s = crNvNum(total);
            return u != null && s != null && s > 0 && u >= 0 ? Math.min(100, (u * 100) / s) : null;
        };

        // one answer of a read the view keeps as a list: not read yet, failed (with why) or the body
        function crNvSlot(read, i) {
            if (!Array.isArray(read)) return { state: 'unread' };
            const f = crNdFail(read[i]);
            return f ? { state: 'failed', fail: f } : { state: 'ok', body: read[i] };
        }

        // --- rules ---------------------------------------------------------------------------------

        // the volume groups of disks/lvm. PVE answers a tree {leaf, children: [vg {name, size, free,
        // lvcount, children: [pv {name, size, free}]}]}; a tree without groups is "none". LW Nov 2026 -
        // a failed read is an error of the route now, so an empty list is "empty" and means none too
        function crNvLvm(body, thins) {
            const tree = !!body && typeof body === 'object' && !Array.isArray(body);
            const list = tree ? (Array.isArray(body.children) ? body.children : []) : (Array.isArray(body) ? body : []);
            const vgs = list.filter(v => v && typeof v === 'object' && (v.name || v.vg)).map(v => {
                const name = String(v.name || v.vg);
                const size = crNvNum(v.size), free = crNvNum(v.free);
                const used = size != null && free != null && free >= 0 && free <= size ? size - free : null;
                return {
                    name, size, free, used, lvcount: crNvNum(v.lvcount),
                    pvs: (Array.isArray(v.children) ? v.children : []).filter(p => p && typeof p === 'object' && p.name)
                        .map(p => ({ name: String(p.name), size: crNvNum(p.size), free: crNvNum(p.free) })),
                    thin: (thins || []).filter(x => x.vg === name).map(x => x.lv),
                };
            });
            return { tree, vgs, state: vgs.length ? 'ok' : tree ? 'none' : 'empty' };
        }

        // the thin pools of disks/lvmthin: data and metadata usage where PVE sent both numbers
        function crNvThin(body) {
            const list = Array.isArray(body) ? body : [];
            return list.filter(x => x && typeof x === 'object' && x.lv).map(x => ({
                lv: String(x.lv), vg: x.vg == null ? '' : String(x.vg),
                size: crNvNum(x.lv_size), used: crNvNum(x.used),
                metaSize: crNvNum(x.metadata_size), metaUsed: crNvNum(x.metadata_used),
            }));
        }

        const CR_NV_ZFS_TONE = { ONLINE: 'success', DEGRADED: 'warning', FAULTED: 'error', UNAVAIL: 'error',
                                 REMOVED: 'error', SUSPENDED: 'error', OFFLINE: 'warning' };
        // the pools of disks/zfs: name, size, alloc, free, frag (percent), dedup (ratio), health
        function crNvZfs(body) {
            const list = Array.isArray(body) ? body : [];
            return list.filter(p => p && typeof p === 'object' && p.name).map(p => {
                const health = p.health == null ? '' : String(p.health).trim();
                return {
                    name: String(p.name), size: crNvNum(p.size), alloc: crNvNum(p.alloc), free: crNvNum(p.free),
                    frag: crNvNum(p.frag), dedup: crNvNum(p.dedup), health,
                    tone: health ? (CR_NV_ZFS_TONE[health.toUpperCase()] || 'neutral') : 'none',
                };
            });
        }

        // the repositories of get_node_repos: enabled, disabled, and the known ones the node does
        // not have (exists false); the update channel of Proxmox VE from its two known entries
        const crNrKey = (r) => String(r.id || `${r.file || ''}#${r.index}`);
        function crNrLine(content) {
            if (!content || typeof content !== 'object') return '';
            const part = (k) => (Array.isArray(content[k]) ? content[k].join(' ') : content[k] == null ? '' : String(content[k]));
            return ['Types', 'URIs', 'Suites', 'Components'].map(part).filter(Boolean).join(' ');
        }
        function crNrModel(list) {
            const rows = (Array.isArray(list) ? list : []).filter(r => r && typeof r === 'object').map(r => ({
                repo: r, key: crNrKey(r), name: String(r.name || r.id || ''), enabled: !!r.enabled, exists: r.exists !== false,
                line: crNrLine(r.content), file: r.actual_file || r.file || '', index: crNvNum(r.index),
                sub: !!r.requires_subscription, other: !!r.is_other,
            }));
            const ent = rows.find(r => r.repo.id === 'pve-enterprise');
            const free = rows.find(r => r.repo.id === 'pve-no-subscription');
            const on = (r) => !!r && r.exists && r.enabled;
            const channel = !ent && !free ? 'unknown' : on(ent) && on(free) ? 'both' : on(ent) ? 'enterprise' : on(free) ? 'free' : 'none';
            // the route matches every known entry by a part of its address, so one line of the node
            // can stand under two names (the enterprise Ceph line under its release and under Ceph Enterprise)
            const seen = {};
            for (const r of rows) {
                if (!r.exists || !r.file || r.index == null) continue;
                const k = `${r.file}#${r.index}`;
                (seen[k] = seen[k] || []).push(r.name);
            }
            const twice = Object.keys(seen).filter(k => seen[k].length > 1).map(k => seen[k]);
            return {
                rows, ent, free, channel, twice,
                groups: { on: rows.filter(r => r.exists && r.enabled), off: rows.filter(r => r.exists && !r.enabled),
                          absent: rows.filter(r => !r.exists) },
            };
        }

        const CR_NX_TONE = { HEALTH_OK: 'success', HEALTH_WARN: 'warning', HEALTH_ERR: 'error' };
        const CR_NX_SEV = { HEALTH_ERR: 3, HEALTH_WARN: 2 };
        // Ceph from ceph/status (ceph -s), ceph/osd, ceph/mon, ceph/pool. The status route answers
        // {available: false} for a PVE 501 and a PVE 500 alike, so for a node without Ceph as well as
        // for an installed Ceph whose cluster did not answer, and {} when the request failed; the
        // three lists come back [] for none as well as for a failed read
        function crNxModel(read) {
            const st = crNvSlot(read, 0);
            if (st.state !== 'ok') return { state: st.state, fail: st.fail };
            const s = st.body;
            if (!s || typeof s !== 'object' || Array.isArray(s)) return { state: 'blank' };
            if (s.available === false) return { state: 'none' };
            if (!Object.keys(s).length) return { state: 'blank' };
            const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
            const health = obj(s.health);
            const status = String(health.status || health.overall_status || '');
            const checks = Object.keys(obj(health.checks)).map(name => {
                const c = obj(health.checks[name]);
                return { name, severity: String(c.severity || ''), message: String(obj(c.summary).message || ''), muted: !!c.muted };
            }).sort((a, b) => (CR_NX_SEV[b.severity] || 0) - (CR_NX_SEV[a.severity] || 0) || a.name.localeCompare(b.name));
            let osdmap = obj(s.osdmap);
            if (osdmap.osdmap && typeof osdmap.osdmap === 'object') osdmap = osdmap.osdmap;  // before Quincy one level deeper
            const pgmap = obj(s.pgmap);
            const monmap = obj(s.monmap);
            const states = (Array.isArray(pgmap.pgs_by_state) ? pgmap.pgs_by_state : []).filter(x => x && typeof x === 'object')
                .map(x => ({ state: String(x.state_name || ''), count: crNvNum(x.count) })).filter(x => x.state && x.count != null)
                .sort((a, b) => b.count - a.count);
            const quorum = Array.isArray(s.quorum_names) ? s.quorum_names.map(String) : null;
            const list = (i) => {
                const x = crNvSlot(read, i);
                if (x.state === 'failed') return { state: 'failed', fail: x.fail, rows: [] };
                const rows = Array.isArray(x.body) ? x.body.filter(r => r && typeof r === 'object') : [];
                return { state: rows.length ? 'ok' : 'empty', rows };
            };
            return {
                state: 'ok', status, tone: CR_NX_TONE[status] || (status ? 'neutral' : 'none'), checks,
                osds: { total: crNvNum(osdmap.num_osds), up: crNvNum(osdmap.num_up_osds), in: crNvNum(osdmap.num_in_osds) },
                pgs: { total: crNvNum(pgmap.num_pgs), states,
                       clean: states.length ? states.filter(x => x.state.split('+').includes('active') && x.state.split('+').includes('clean')).reduce((n, x) => n + x.count, 0) : null },
                bytes: { used: crNvNum(pgmap.bytes_used), avail: crNvNum(pgmap.bytes_avail), total: crNvNum(pgmap.bytes_total) },
                mons: { total: crNvNum(monmap.num_mons) ?? (Array.isArray(monmap.mons) ? monmap.mons.length : null), quorum },
                osd: list(1), mon: list(2), pool: list(3),
            };
        }

        window.PegaProxNodeStore = Object.freeze({ lvm: crNvLvm, thin: crNvThin, zfs: crNvZfs, repos: crNrModel, ceph: crNxModel });

        // --- parts ---------------------------------------------------------------------------------

        // how much of a total is used: a bar and "X of Y (Z%)"; a missing number says so.
        // tone: 'auto' by the storage pair of the redesign (crStoreTone: from 70 % warning, above 85 %
        // error), 'info' for a plain share
        function CrNvUsage({ id, used, total, tone = 'auto', label }) {
            const { t } = useTranslation();
            const pct = crNvPct(used, total);
            if (pct == null) return <CrNcMissing />;
            const tn = tone === 'auto' ? crStoreTone(pct) : tone;
            return (
                <span className={`cr-nv-usage cr-nv-tone-${tn}`} data-cr-nv-usage={id} data-cr-nv-pct={pct.toFixed(1)} data-cr-nv-tone={tn}
                    title={tone === 'auto' ? crStoreScale(t) : undefined}>
                    <span className="cr-nv-bar" aria-hidden="true"><span style={{ width: `${pct}%` }} /></span>
                    <span className="cr-nv-usage-text">{crNnT(t, label || 'crNvUsedOf', { used: formatBytes(crNvNum(used)), total: formatBytes(crNvNum(total)), pct: pct.toFixed(1) })}</span>
                </span>
            );
        }

        // the read states every list of these sections shares: not read yet, failed with why,
        // and an empty answer that can also be a failed read
        function crNvReadState(t, { id, slot, loading, onRetry, emptyText }) {
            if (slot.state === 'unread') {
                return <CrNcState id={id} kind={loading ? 'loading' : 'empty'} onRetry={loading ? undefined : onRetry}>{loading ? undefined : t('crNcNotRead')}</CrNcState>;
            }
            if (slot.state === 'failed') {
                return <CrNcState id={id} kind="error" onRetry={onRetry} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, slot.fail) })}</CrNcState>;
            }
            if (emptyText) return <CrNcState id={id} kind="empty" onRetry={onRetry} retryDisabled={loading}>{emptyText}</CrNcState>;
            return null;
        }

        function CrNvRefresh({ id, loading, onClick }) {
            const { t } = useTranslation();
            return <CrButton icon={<Icons.RotateCw />} onClick={onClick} disabled={loading} data-cr-nv-refresh={id}>{t('refresh')}</CrButton>;
        }

        // --- disk and storage actions (round 10) ----------------------------------------------------
        // What the classic node dialog (NodeModal) can do with the disks of a Proxmox VE node, with its
        // requests: Initialize GPT and Wipe on a disk PVE lists as unused, and a new LVM volume group,
        // LVM-Thin pool, directory or ZFS pool. A create shows what it will send before it goes, a
        // destructive one names the disk and waits for its device name typed in. Every write takes
        // storage.config on the server and none runs on a read-only standby. After an answer the
        // disks read is made again (disks, lvm, lvmthin, zfs once each); nothing is drawn before then.

        // the form the classic dialog opens with (openDiskModal)
        const CR_DO_FORM = { device: '', name: '', vgname: '', devices: [], raidlevel: 'single', compression: 'on', ashift: 12,
                             filesystem: 'ext4', add_storage: true };
        // PVE takes at least this many disks for a level (the classic dialog says the same in its hint)
        const CR_DO_RAID_MIN = { single: 1, mirror: 2, raid10: 4, raidz: 3, raidz2: 4, raidz3: 5 };
        const CR_DO_RAID = [['single', 'Single'], ['mirror', 'Mirror'], ['raid10', 'RAID10'], ['raidz', 'RAIDZ'], ['raidz2', 'RAIDZ2'], ['raidz3', 'RAIDZ3']];
        const CR_DO_COMP = [['on', 'On (LZ4)'], ['off', 'Off'], ['lz4', 'LZ4'], ['zstd', 'ZSTD'], ['gzip', 'GZIP'], ['lzjb', 'LZJB']];
        const CR_DO_ASHIFT = [[9, '9 (512B)'], [12, '12 (4K)'], [13, '13 (8K)']];
        const CR_DO_FS = [['ext4', 'ext4'], ['xfs', 'XFS']];
        const CR_DO_TYPES = {
            lvm: { title: 'crDoNewLvmTitle', label: 'crDoLvm', btn: 'crDoNewLvm', what: 'crDoWhatLvm', name: 'myvg' },
            lvmthin: { title: 'crDoNewThinTitle', label: 'crDoThin', btn: 'crDoNewThin', what: 'crDoWhatThin', name: 'data' },
            directory: { title: 'crDoNewDirTitle', label: 'crDoDir', btn: 'crDoNewDir', what: 'crDoWhatDir', name: 'storage' },
            zfs: { title: 'crDoNewZfsTitle', label: 'crDoZfs', btn: 'crDoNewZfs', what: 'crDoWhatZfs', name: 'tank' },
        };
        const CR_DO_DANGER = {
            initgpt: { endpoint: 'disks/initgpt', title: 'crDoGptTitle', lost: 'crDoGptLost', go: 'crDoGptGo', busy: 'crDoGptBusy', what: 'crDoWhatGpt' },
            wipe: { endpoint: 'disks/wipe', title: 'crDoWipeTitle', lost: 'crDoWipeLost', go: 'crDoWipeGo', busy: 'crDoWipeBusy', what: 'crDoWhatWipe' },
        };

        // --- rules ---

        // a disk the classic dialog offers for Initialize GPT, Wipe and as a device of a new storage
        const crDoIsUnused = (d) => !!d && typeof d === 'object' && (d.used === 'unused' || !d.used);
        const crDoUnused = (list) => (Array.isArray(list) ? list.filter(crDoIsUnused).filter(d => d.devpath) : []);

        // the request createDisk of the classic dialog sends for a type, from its form
        function crDoBody(type, f) {
            if (type === 'lvm') return { endpoint: 'disks/lvm', body: { device: f.device, name: f.name, add_storage: f.add_storage } };
            if (type === 'lvmthin') return { endpoint: 'disks/lvmthin', body: { device: f.vgname, name: f.name, add_storage: f.add_storage } };
            if (type === 'zfs') {
                return { endpoint: 'disks/zfs', body: { devices: f.devices, name: f.name, raidlevel: f.raidlevel, compression: f.compression,
                                                         ashift: f.ashift, add_storage: f.add_storage } };
            }
            if (type === 'directory') return { endpoint: 'disks/directory', body: { device: f.device, name: f.name, filesystem: f.filesystem, add_storage: f.add_storage } };
            return null;
        }

        // the classic Create button: a name, and the device, the volume group or one disk
        function crDoValid(type, f) {
            if (!f || !f.name) return false;
            if (type === 'lvm' || type === 'directory') return !!f.device;
            if (type === 'lvmthin') return !!f.vgname;
            if (type === 'zfs') return Array.isArray(f.devices) && f.devices.length > 0;
            return false;
        }

        // Initialize GPT sends the classic { disk }. The wipe route refuses a body without
        // confirm_name equal to the disk (datacenter.py), which is what the typed name confirms
        const crDoDiskBody = (kind, devpath) => (kind === 'wipe' ? { disk: devpath, confirm_name: devpath } : { disk: devpath });

        // who may change the disks: the routes take storage.config, a read-only standby changes nothing
        function useCrDoGate() {
            const { t } = useTranslation();
            const { user, isAdmin, haReadOnly } = useAuth();
            return useMemo(() => {
                const perms = Array.isArray(user && user.permissions) ? user.permissions : [];
                if (haReadOnly) return { ok: false, kind: 'standby', why: t('crDoWhyStandby') };
                if (!isAdmin && !perms.includes('storage.config')) return { ok: false, kind: 'perm', why: t('crDoWhyPerm') };
                return { ok: true, kind: '', why: '' };
            }, [user, isAdmin, haReadOnly, t]);
        }

        // one write at a time per card: the open dialog, the request and its answer. A refusal stays
        // in the dialog with what the server said; an accepted one closes it and says so on the card
        function useCrDoOps({ clusterId, node, authFetch, onReload }) {
            const [dlg, setDlg] = useState(null);     // { kind: create|initgpt|wipe, type, disk, fail }
            const [busy, setBusy] = useState(false);
            const [done, setDone] = useState(null);   // { what, task } of the last accepted write
            const alive = useRef(true);
            useEffect(() => () => { alive.current = false; }, []);
            const base = `${API_URL}/clusters/${encodeURIComponent(clusterId)}/nodes/${encodeURIComponent(node)}`;
            const open = (d) => { setDone(null); setDlg({ ...d, fail: null }); };
            const close = () => { if (!busy) setDlg(null); };
            const send = async (what, endpoint, body) => {
                setBusy(true);
                setDlg(d => (d ? { ...d, fail: null } : d));
                const ans = await crNdRead(await authFetch(`${base}/${endpoint}`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }));
                if (!alive.current) return;
                const fail = crNdFail(ans);
                setBusy(false);
                if (fail) setDlg(d => (d ? { ...d, fail } : d));
                else {
                    setDlg(null);
                    setDone({ what, task: ans && typeof ans.task === 'string' ? ans.task : '' });
                }
                if (onReload) onReload();
            };
            return { dlg, busy, done, open, close, send, dismiss: () => setDone(null) };
        }

        // --- parts ---

        // why the writes of a card are off, said once under its actions
        function CrDoGate({ gate }) {
            if (!gate || gate.ok) return null;
            return <p className="cr-nc-note cr-muted cr-do-gate" data-cr-do-gate={gate.kind}>{gate.why}</p>;
        }

        // the answer of an accepted write: PVE runs it as a task, the lists show it when that is done
        function CrDoDone({ done, onDismiss }) {
            const { t } = useTranslation();
            if (!done) return null;
            return (
                <div className="cr-callout cr-nc-callout cr-do-done" role="status" data-cr-do-done="">
                    <Icons.CheckCircle className="w-4 h-4" />
                    <div>
                        <p className="cr-strong">{crNnT(t, 'crDoDone', { what: done.what })}</p>
                        <p className="cr-muted">
                            {done.task ? <>{t('crDoTask')} <span className="cr-mono cr-do-upid" data-cr-do-task="">{done.task}</span></> : t('crDoNoTask')}
                        </p>
                        <p className="cr-muted">{t('crDoReread')}</p>
                    </div>
                    <button type="button" className="cr-btn cr-btn-xs" onClick={onDismiss} data-cr-do-dismiss="">{t('close')}</button>
                </div>
            );
        }

        function CrDoRefused({ fail }) {
            const { t } = useTranslation();
            if (!fail) return null;
            return (
                <div className="cr-callout cr-callout-error" role="alert" data-cr-do-error="">
                    <Icons.AlertCircle className="w-4 h-4" />
                    <div>{crNnT(t, 'crDoRefused', { why: crNdWhy(t, fail) })}</div>
                </div>
            );
        }

        const crDoDiskLine = (d) => `${d.devpath} - ${crNvBytes(d.size) || '?'} (${d.type || 'hdd'})`;

        // Initialize GPT or Wipe of one disk: what is lost, and the device name typed in before it arms
        function CrDoDiskDialog({ kind, node, disk, busy, fail, onCancel, onSend }) {
            const { t } = useTranslation();
            const [typed, setTyped] = useState('');
            const k = CR_DO_DANGER[kind];
            const dev = crNdDev(disk.devpath);
            const armed = !!dev && typed.trim() === dev;
            const ident = [disk.model, disk.serial].map(x => String(x || '').trim()).filter(Boolean).join(' · ');
            const what = crNnT(t, k.what, { disk: disk.devpath });
            return (
                <CrNcConfirm id={`do-${kind}`} title={crNnT(t, k.title, { disk: disk.devpath, node })} goLabel={t(k.go)} busyLabel={t(k.busy)}
                    busy={busy} goDisabled={!armed} onCancel={onCancel} onConfirm={() => onSend(what, k.endpoint, crDoDiskBody(kind, disk.devpath))}>
                    <CrNcKv id={`do-${kind}`} rows={[
                        { k: 'disk', label: t('crNdDisk'), value: disk.devpath, mono: true },
                        { k: 'ident', label: t('crDoIdent'), value: ident },
                        { k: 'size', label: t('crNvSize'), value: crNvBytes(disk.size) },
                        { k: 'used', label: t('crNdUsedBy'), value: t('crDoUnusedPve') },
                    ]} />
                    <div className="cr-callout cr-callout-error" role="note" data-cr-do-lost={kind}>
                        <Icons.AlertTriangle className="w-4 h-4" />
                        <div>
                            <p className="cr-strong">{crNnT(t, 'crDoLostTitle', { disk: disk.devpath, node })}</p>
                            <p>{crNnT(t, k.lost, { disk: disk.devpath })}</p>
                        </div>
                    </div>
                    <CrDoRefused fail={fail} />
                    <label className="cr-nn-typename" data-cr-do-typename="">
                        <span>{crNnT(t, 'crDoTypeName', { dev })}</span>
                        <input type="text" className="cr-input cr-nc-mono-input" value={typed} onChange={e => setTyped(e.target.value)} disabled={busy}
                            autoComplete="off" spellCheck={false} data-cr-do-typename-input="" aria-label={crNnT(t, 'crDoTypeName', { dev })} />
                    </label>
                </CrNcConfirm>
            );
        }

        // a new LVM volume group, LVM-Thin pool, directory or ZFS pool: the classic form, then what
        // will be created, then the classic request
        function CrDoCreateDialog({ type, node, disks, disksWhy, vgs, busy, fail, onCancel, onSend }) {
            const { t } = useTranslation();
            const [f, setF] = useState(() => ({ ...CR_DO_FORM, devices: [] }));
            const [step, setStep] = useState('form');
            const set = (k, v) => setF(p => ({ ...p, [k]: v }));
            const kind = CR_DO_TYPES[type];
            const unused = crDoUnused(disks);
            const ok = crDoValid(type, f);
            const req = crDoBody(type, f);
            const min = CR_DO_RAID_MIN[f.raidlevel] || 1;
            const raidName = (CR_DO_RAID.find(x => x[0] === f.raidlevel) || [])[1] || f.raidlevel;
            const devWhat = type === 'zfs' ? f.devices.join(', ') : type === 'lvmthin' ? f.vgname : f.device;
            const what = crNnT(t, kind.what, { name: f.name, dev: devWhat, raid: raidName, fs: f.filesystem });
            const noDisks = disks == null
                ? crNnT(t, 'crDoDisksNotRead', { node, why: disksWhy || t('crNdNoAnswer') })
                : crNnT(t, 'crDoNoUnused', { node });
            const devField = (
                <CrNcField id="do-device" label={t('crDoDevice')} hint={unused.length ? undefined : noDisks} hintTone={unused.length ? undefined : 'warning'}>
                    <select id="cr-nc-do-device" className="cr-select" value={f.device} disabled={busy} onChange={e => set('device', e.target.value)} data-cr-do-field="device">
                        <option value="">{t('crDoPickDisk')}</option>
                        {unused.map(d => <option key={d.devpath} value={d.devpath}>{crDoDiskLine(d)}</option>)}
                    </select>
                </CrNcField>
            );
            const form = (
                <div className="cr-nc-form" data-cr-do-form={type}>
                    {(type === 'lvm' || type === 'directory') && devField}
                    {type === 'lvmthin' && (
                        <CrNcField id="do-vg" label={t('crDoVg')} hint={vgs && vgs.length ? undefined : crNnT(t, 'crDoNoVg', { node })} hintTone={vgs && vgs.length ? undefined : 'warning'}>
                            <select id="cr-nc-do-vg" className="cr-select" value={f.vgname} disabled={busy} onChange={e => set('vgname', e.target.value)} data-cr-do-field="vgname">
                                <option value="">{t('crDoPickVg')}</option>
                                {(vgs || []).map(v => (
                                    <option key={v.name} value={v.name}>{crNnT(t, 'crDoVgLine', { vg: v.name, free: crNvBytes(v.free) || '?', size: crNvBytes(v.size) || '?' })}</option>
                                ))}
                            </select>
                        </CrNcField>
                    )}
                    {type === 'zfs' && (
                        <CrNcField id="do-devices" label={t('crDoDevices')} wide
                            hint={!unused.length ? noDisks : f.devices.length && f.devices.length < min ? crNnT(t, 'crDoRaidMin', { level: raidName, n: min, k: f.devices.length }) : undefined}
                            hintTone={!unused.length || (f.devices.length && f.devices.length < min) ? 'warning' : undefined}>
                            <div className="cr-do-devs" role="group" aria-label={t('crDoDevices')} data-cr-do-field="devices">
                                {unused.map(d => (
                                    <label key={d.devpath} className="cr-nn-ack cr-do-dev">
                                        <input type="checkbox" checked={f.devices.includes(d.devpath)} disabled={busy} data-cr-do-dev={crNdDev(d.devpath)}
                                            onChange={e => set('devices', e.target.checked ? [...f.devices, d.devpath] : f.devices.filter(x => x !== d.devpath))} />
                                        <span className="cr-mono">{d.devpath}</span>
                                        <span className="cr-muted">{crNvBytes(d.size) || '?'}, {d.type || 'hdd'}</span>
                                    </label>
                                ))}
                            </div>
                        </CrNcField>
                    )}
                    <CrNcField id="do-name" label={type === 'lvmthin' || type === 'zfs' ? t('crDoPoolName') : t('crDoName')}>
                        <input id="cr-nc-do-name" type="text" className="cr-input cr-nc-mono-input" value={f.name} placeholder={kind.name} disabled={busy}
                            autoComplete="off" spellCheck={false} onChange={e => set('name', e.target.value)} data-cr-do-field="name" />
                    </CrNcField>
                    {type === 'zfs' && (
                        <>
                            <CrNcField id="do-raid" label={t('crDoRaid')}>
                                <select id="cr-nc-do-raid" className="cr-select" value={f.raidlevel} disabled={busy} onChange={e => set('raidlevel', e.target.value)} data-cr-do-field="raidlevel">
                                    {CR_DO_RAID.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                                </select>
                            </CrNcField>
                            <CrNcField id="do-comp" label={t('crDoCompression')}>
                                <select id="cr-nc-do-comp" className="cr-select" value={f.compression} disabled={busy} onChange={e => set('compression', e.target.value)} data-cr-do-field="compression">
                                    {CR_DO_COMP.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                                </select>
                            </CrNcField>
                            <CrNcField id="do-ashift" label="ashift" hint={t('crDoAshiftHint')}>
                                <select id="cr-nc-do-ashift" className="cr-select" value={f.ashift} disabled={busy} onChange={e => set('ashift', parseInt(e.target.value, 10))} data-cr-do-field="ashift">
                                    {CR_DO_ASHIFT.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                                </select>
                            </CrNcField>
                        </>
                    )}
                    {type === 'directory' && (
                        <CrNcField id="do-fs" label={t('crDoFs')}>
                            <select id="cr-nc-do-fs" className="cr-select" value={f.filesystem} disabled={busy} onChange={e => set('filesystem', e.target.value)} data-cr-do-field="filesystem">
                                {CR_DO_FS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                            </select>
                        </CrNcField>
                    )}
                    <label className="cr-nn-ack cr-nc-field-wide" data-cr-do-field="add_storage">
                        <input type="checkbox" checked={f.add_storage} disabled={busy} onChange={e => set('add_storage', e.target.checked)} />
                        <span>{t('crDoAddStorage')}</span>
                    </label>
                </div>
            );
            const rows = [
                { k: 'what', label: t('crDoWhat'), value: t(kind.label) },
                { k: 'node', label: t('node'), value: node },
                type === 'lvmthin' ? { k: 'vg', label: t('crDoVg'), value: f.vgname, mono: true }
                    : { k: 'device', label: type === 'zfs' ? t('crDoDevices') : t('crDoDevice'), value: devWhat, mono: true },
                { k: 'name', label: type === 'lvmthin' || type === 'zfs' ? t('crDoPoolName') : t('crDoName'), value: f.name, mono: true },
                type === 'zfs' && { k: 'raid', label: t('crDoRaid'), value: raidName },
                type === 'zfs' && { k: 'compression', label: t('crDoCompression'), value: (CR_DO_COMP.find(x => x[0] === f.compression) || [])[1] || f.compression },
                type === 'zfs' && { k: 'ashift', label: 'ashift', value: String(f.ashift) },
                type === 'directory' && { k: 'fs', label: t('crDoFs'), value: f.filesystem },
                { k: 'storage', label: t('crDoStorage'), value: f.add_storage ? crNnT(t, 'crDoStorageYes', { name: f.name }) : t('crDoStorageNo') },
            ];
            const review = (
                <div className="cr-nc-confirm" data-cr-do-review={type}>
                    <p>{crNnT(t, 'crDoReviewLead', { node })}</p>
                    <CrNcKv id="do-review" rows={rows} />
                    {type !== 'lvmthin' && (
                        <div className="cr-callout cr-callout-warning" role="note" data-cr-do-format="">
                            <Icons.AlertTriangle className="w-4 h-4" />
                            <div>{crNnT(t, type === 'zfs' && f.devices.length > 1 ? 'crDoFormatN' : 'crDoFormatOne', { dev: devWhat })}</div>
                        </div>
                    )}
                    {type === 'zfs' && f.devices.length < min && (
                        <p className="cr-nc-hint cr-nc-hint-warning" data-cr-do-raidmin="">{crNnT(t, 'crDoRaidMin', { level: raidName, n: min, k: f.devices.length })}</p>
                    )}
                    <CrDoRefused fail={fail} />
                </div>
            );
            return (
                <CrUpdDialog id={`do-new-${type}`} title={crNnT(t, kind.title, { node })} sub={step === 'review' ? t('crDoReviewSub') : undefined}
                    busy={busy} onCancel={onCancel} sticky
                    footer={step === 'form' ? (
                        <>
                            <CrButton onClick={onCancel} data-cr-do-cancel="">{t('cancel')}</CrButton>
                            <CrButton variant="primary" onClick={() => setStep('review')} disabled={!ok} data-cr-do-next="">{t('crDoReview')}</CrButton>
                        </>
                    ) : (
                        <>
                            <CrButton onClick={() => setStep('form')} disabled={busy} data-cr-do-back="">{t('crDoBack')}</CrButton>
                            <CrButton variant="primary" onClick={() => onSend(what, req.endpoint, req.body)} disabled={busy || !ok} data-cr-do-go="">
                                {busy ? t('crDoCreating') : t('crDoCreate')}
                            </CrButton>
                        </>
                    )}>
                    {step === 'form' ? form : review}
                </CrUpdDialog>
            );
        }

        // the dialog a card has open, if any
        function CrDoDialogs({ ops, node, disks, disksWhy, vgs }) {
            const d = ops.dlg;
            if (!d) return null;
            if (d.kind === 'create') {
                return <CrDoCreateDialog type={d.type} node={node} disks={disks} disksWhy={disksWhy} vgs={vgs} busy={ops.busy} fail={d.fail}
                    onCancel={ops.close} onSend={ops.send} />;
            }
            return <CrDoDiskDialog kind={d.kind} node={node} disk={d.disk} busy={ops.busy} fail={d.fail} onCancel={ops.close} onSend={ops.send} />;
        }

        // the button that opens a create dialog; off with why where the gate is closed
        function CrDoNew({ type, ops, gate, variant = 'default', short }) {
            const { t } = useTranslation();
            return (
                <CrButton variant={variant} icon={<Icons.Plus />} onClick={() => ops.open({ kind: 'create', type })} disabled={!gate.ok || ops.busy}
                    title={gate.ok ? undefined : gate.why} data-cr-do-new={type}>
                    {t(short ? CR_DO_TYPES[type].label : CR_DO_TYPES[type].btn)}
                </CrButton>
            );
        }

        // the disks and the volume groups a create dialog offers, from the one disks read
        function crDoLists(read, t) {
            const ds = crNvSlot(read, 0);
            const ls = crNvSlot(read, 1);
            return {
                disks: ds.state === 'ok' && Array.isArray(ds.body) ? ds.body : null,
                disksWhy: ds.state === 'failed' ? crNdWhy(t, ds.fail) : ds.state === 'unread' ? t('crNcNotRead') : '',
                vgs: ls.state === 'ok' ? crNvLvm(ls.body, []).vgs : [],
            };
        }

        window.PegaProxNodeDiskOps = Object.freeze({ body: crDoBody, valid: crDoValid, unused: crDoUnused, diskBody: crDoDiskBody, raidMin: CR_DO_RAID_MIN });

        // --- LVM ----------------------------------------------------------------------------------

        function CrNodeLvm({ clusterId, node, read, loading, onReload, authFetch }) {
            const { t } = useTranslation();
            const gate = useCrDoGate();
            const ops = useCrDoOps({ clusterId, node, authFetch, onReload });
            const slot = crNvSlot(read, 1);
            const thinSlot = crNvSlot(read, 2);
            const thins = thinSlot.state === 'ok' ? crNvThin(thinSlot.body) : [];
            const m = slot.state === 'ok' ? crNvLvm(slot.body, thins) : null;
            const body = () => {
                const st = crNvReadState(t, { id: 'lvm', slot, loading, onRetry: onReload,
                    emptyText: m && (m.state === 'empty' || m.state === 'none') ? t('crNvLvmNone') : '' });
                if (st) return st;
                return (
                    <div className="cr-nn-scroll">
                        <table className="corp-datagrid cr-table cr-nn-table cr-nv-table" aria-label={t('crNvVgs')}>
                            <thead>
                                <tr>
                                    <th>{t('crNvVg')}</th><th className="cr-nh-num">{t('crNvSize')}</th><th className="cr-nh-num">{t('crNvFree')}</th>
                                    <th>{t('crNvAllocated')}</th><th className="cr-nh-num">{t('crNvLvs')}</th>
                                    {thinSlot.state === 'ok' && <th>{t('crNvThinPools')}</th>}<th>{t('crNvPvs')}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {m.vgs.map(vg => (
                                    <tr key={vg.name} data-cr-nv-vg={vg.name}>
                                        <td className="cr-mono cr-strong">{vg.name}</td>
                                        <td className="cr-nh-num" data-cr-nc-k="size">{crNvBytes(vg.size) || <CrNcMissing />}</td>
                                        <td className="cr-nh-num" data-cr-nc-k="free">{crNvBytes(vg.free) || <CrNcMissing />}</td>
                                        <td data-cr-nc-k="alloc"><CrNvUsage id={`vg-${vg.name}`} used={vg.used} total={vg.size} tone="info" label="crNvAllocOf" /></td>
                                        <td className="cr-nh-num" data-cr-nc-k="lvs">{vg.lvcount != null ? String(vg.lvcount) : <CrNcMissing />}</td>
                                        {thinSlot.state === 'ok' && (
                                            <td data-cr-nc-k="thin">
                                                {vg.thin.length ? <span className="cr-nc-chips">{vg.thin.map(n => <span key={n} className="cr-nn-chip cr-mono">{n}</span>)}</span>
                                                    : <CrNcMissing text={t('crNvNone')} />}
                                            </td>
                                        )}
                                        <td data-cr-nc-k="pvs">
                                            {vg.pvs.length ? (
                                                <ul className="cr-nv-pvs">
                                                    {vg.pvs.map(pv => (
                                                        <li key={pv.name} data-cr-nv-pv={pv.name}>
                                                            <span className="cr-mono">{pv.name}</span>
                                                            <span className="cr-muted">{crNnT(t, 'crNvPvSize', { size: crNvBytes(pv.size) || t('crNsNotReported'), free: crNvBytes(pv.free) || t('crNsNotReported') })}</span>
                                                        </li>
                                                    ))}
                                                </ul>
                                            ) : <CrNcMissing />}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                );
            };
            return (
                <CrNcSection id="lvm" title={t('lvmStorage')} desc={t('crNvLvmDesc')}
                    badge={m && m.vgs.length ? <span className="cr-muted cr-nn-count">{crNnT(t, m.vgs.length === 1 ? 'crNvVgOne' : 'crNvVgN', { n: m.vgs.length })}</span> : null}
                    actions={<><CrDoNew type="lvm" ops={ops} gate={gate} /><CrNvRefresh id="lvm" loading={loading} onClick={onReload} /></>}>
                    <CrDoGate gate={gate} />
                    <CrDoDone done={ops.done} onDismiss={ops.dismiss} />
                    {body()}
                    {m && m.vgs.length > 0 && <p className="cr-nc-note cr-muted" data-cr-nv-note="lvm">{t('crNvAllocNote')}</p>}
                    <CrDoDialogs ops={ops} node={node} {...crDoLists(read, t)} />
                </CrNcSection>
            );
        }

        // --- LVM-Thin -----------------------------------------------------------------------------

        function CrNodeLvmThin({ clusterId, node, read, loading, onReload, authFetch }) {
            const { t } = useTranslation();
            const gate = useCrDoGate();
            const ops = useCrDoOps({ clusterId, node, authFetch, onReload });
            const slot = crNvSlot(read, 2);
            const pools = slot.state === 'ok' ? crNvThin(slot.body) : null;
            const body = () => {
                const st = crNvReadState(t, { id: 'lvmthin', slot, loading, onRetry: onReload,
                    emptyText: pools && !pools.length ? t('crNvThinEmpty') : '' });
                if (st) return st;
                return (
                    <div className="cr-nn-scroll">
                        <table className="corp-datagrid cr-table cr-nn-table cr-nv-table" aria-label={t('crNvThinPools')}>
                            <thead>
                                <tr>
                                    <th>{t('crNvPool')}</th><th>{t('crNvVg')}</th><th className="cr-nh-num">{t('crNvSize')}</th>
                                    <th>{t('crNvThinData')}</th><th>{t('crNvThinMeta')}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {pools.map(p => (
                                    <tr key={`${p.vg}/${p.lv}`} data-cr-nv-thin={`${p.vg}/${p.lv}`}>
                                        <td className="cr-mono cr-strong">{p.lv}</td>
                                        <td className="cr-mono" data-cr-nc-k="vg">{p.vg || <CrNcMissing />}</td>
                                        <td className="cr-nh-num" data-cr-nc-k="size">{crNvBytes(p.size) || <CrNcMissing />}</td>
                                        <td data-cr-nc-k="data"><CrNvUsage id={`thin-${p.lv}`} used={p.used} total={p.size} /></td>
                                        <td data-cr-nc-k="meta"><CrNvUsage id={`thin-${p.lv}-meta`} used={p.metaUsed} total={p.metaSize} /></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                );
            };
            return (
                <CrNcSection id="lvmthin" title={t('lvmThinStorage')} desc={t('crNvThinDesc')}
                    badge={pools && pools.length ? <span className="cr-muted cr-nn-count">{crNnT(t, pools.length === 1 ? 'crNvPoolOne' : 'crNvPoolN', { n: pools.length })}</span> : null}
                    actions={<><CrDoNew type="lvmthin" ops={ops} gate={gate} /><CrNvRefresh id="lvmthin" loading={loading} onClick={onReload} /></>}>
                    <CrDoGate gate={gate} />
                    <CrDoDone done={ops.done} onDismiss={ops.dismiss} />
                    {body()}
                    {pools && pools.length > 0 && <p className="cr-nc-note cr-muted" data-cr-nv-note="lvmthin">{t('crNvThinNote')}</p>}
                    <CrDoDialogs ops={ops} node={node} {...crDoLists(read, t)} />
                </CrNcSection>
            );
        }

        // --- ZFS ----------------------------------------------------------------------------------

        function CrNodeZfs({ clusterId, node, read, loading, onReload, pool, onPool, authFetch }) {
            const { t } = useTranslation();
            const gate = useCrDoGate();
            const ops = useCrDoOps({ clusterId, node, authFetch, onReload });
            const slot = crNvSlot(read, 3);
            const pools = slot.state === 'ok' ? crNvZfs(slot.body) : null;
            const bad = pools ? pools.filter(p => p.tone === 'warning' || p.tone === 'error').length : 0;
            const body = () => {
                const st = crNvReadState(t, { id: 'zfs', slot, loading, onRetry: onReload,
                    emptyText: pools && !pools.length ? t('crNvZfsEmpty') : '' });
                if (st) return st;
                return (
                    <div className="cr-nn-scroll">
                        <table className="corp-datagrid cr-table cr-nn-table cr-nv-table" aria-label={t('zfsStorage')}>
                            <thead>
                                <tr>
                                    <th>{t('crNvPool')}</th><th>{t('crNvHealth')}</th><th className="cr-nh-num">{t('crNvSize')}</th>
                                    <th>{t('crNvAllocated')}</th><th className="cr-nh-num">{t('crNvFree')}</th>
                                    <th className="cr-nh-num">{t('crNvFrag')}</th><th className="cr-nh-num">{t('crNvDedup')}</th><th aria-label={t('details')} />
                                </tr>
                            </thead>
                            <tbody>
                                {pools.map(p => {
                                    const open = pool === p.name;
                                    return (
                                        <tr key={p.name} className={open ? 'cr-nv-open' : undefined} data-cr-nv-pool={p.name}>
                                            <td className="cr-mono cr-strong">{p.name}</td>
                                            <td>
                                                <span data-cr-nv-health={p.tone}>
                                                    {p.health
                                                        ? <CrBadge tone={p.tone} dot={p.tone !== 'neutral'}>{p.health}</CrBadge>
                                                        : <CrBadge tone="neutral" dot={false}>{t('crNvHealthNone')}</CrBadge>}
                                                </span>
                                            </td>
                                            <td className="cr-nh-num" data-cr-nc-k="size">{crNvBytes(p.size) || <CrNcMissing />}</td>
                                            <td data-cr-nc-k="alloc"><CrNvUsage id={`zfs-${p.name}`} used={p.alloc} total={p.size} label="crNvAllocOf" /></td>
                                            <td className="cr-nh-num" data-cr-nc-k="free">{crNvBytes(p.free) || <CrNcMissing />}</td>
                                            <td className="cr-nh-num" data-cr-nc-k="frag">{p.frag != null ? `${p.frag}%` : <CrNcMissing />}</td>
                                            <td className="cr-nh-num" data-cr-nc-k="dedup">{p.dedup != null ? `${p.dedup.toFixed(2)}x` : <CrNcMissing />}</td>
                                            <td className="cr-nv-acts-cell">
                                                <CrButton className="cr-btn-xs" onClick={() => onPool(open ? null : p.name)} data-zfs-open={p.name}
                                                    aria-pressed={open} title={t('zfsPoolDetails')}>
                                                    {open ? t('crNvHideDetails') : t('details')}
                                                </CrButton>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                );
            };
            return (
                <CrNcSection id="zfs" title={t('zfsStorage')} desc={t('crNvZfsDesc')}
                    badge={pools && pools.length ? (
                        <>
                            <span className="cr-muted cr-nn-count">{crNnT(t, pools.length === 1 ? 'crNvPoolOne' : 'crNvPoolN', { n: pools.length })}</span>
                            {bad > 0 && <span data-cr-nv-zfs-bad=""><CrBadge tone="warning">{crNnT(t, 'crNvZfsBad', { n: bad })}</CrBadge></span>}
                        </>
                    ) : null}
                    actions={<><CrDoNew type="zfs" ops={ops} gate={gate} /><CrNvRefresh id="zfs" loading={loading} onClick={onReload} /></>}>
                    <CrDoGate gate={gate} />
                    <CrDoDone done={ops.done} onDismiss={ops.dismiss} />
                    {body()}
                    {/* the pool picked above, in full: the shared detail view (its own read per click) */}
                    {pool && <ZfsPoolDetail corporate clusterId={clusterId} node={node} pool={pool} onClose={() => onPool(null)} />}
                    <CrDoDialogs ops={ops} node={node} {...crDoLists(read, t)} />
                </CrNcSection>
            );
        }

        // --- Repositories -------------------------------------------------------------------------

        // the reason no switch is offered for an entry that is not set up, said once above that group
        const CR_NR_WHY_ID = 'cr-nr-why-absent';

        // pending: the state the switch asks for, undefined when nothing waits for this one
        function CrNrItem({ r, pending, readOnly, busy, onFlip }) {
            const { t } = useTranslation();
            const waits = pending !== undefined;
            const state = !r.exists ? 'absent' : r.enabled ? 'on' : 'off';
            const label = state === 'absent' ? t('crNrAbsent') : state === 'on' ? t('crNrOn') : t('crNrOff');
            // LW Nov 2026 - the node refuses to switch an entry it does not have (400, manual setup), so
            // no switch is offered for one; one that already waits can still be undone
            const noSwitch = state === 'absent' && !waits;
            const about = r.repo.description ? String(r.repo.description) : '';
            return (
                <tr className={waits ? 'cr-nn-row-pending' : undefined} data-cr-nr-repo={r.key} data-cr-nr-state={state}
                    data-cr-nr-pending={waits ? '' : undefined}>
                    <td className="cr-nr-name">
                        <span className="cr-nr-title">
                            <span className="cr-strong">{r.name || <CrNcMissing />}</span>
                            {r.sub && <span className="cr-nn-chip" data-cr-nr-sub="">{t('crNrNeedsSub')}</span>}
                            {r.other && <span className="cr-nn-chip" data-cr-nr-other="">{t('crNrOther')}</span>}
                        </span>
                        {about && about !== r.name && <span className="cr-muted cr-nr-about" data-cr-nc-k="desc">{about}</span>}
                    </td>
                    <td className="cr-nr-state">
                        <CrBadge tone={state === 'on' ? 'success' : 'neutral'} dot={state === 'on'}>{label}</CrBadge>
                        {waits && <span className="cr-nn-pend" data-cr-nr-will="">{t(pending ? 'crNrWillEnable' : 'crNrWillDisable')}</span>}
                    </td>
                    <td className="cr-nr-src">
                        <span className={r.exists ? 'cr-mono cr-nr-line' : 'cr-nr-line'} data-cr-nc-k="line">
                            {r.exists ? (r.line || <CrNcMissing />) : <CrNcMissing text={t('crNrAbsentLine')} />}
                        </span>
                        {r.exists && (
                            <span className="cr-nr-file" data-cr-nc-k="file">
                                {r.file ? <span className="cr-mono">{r.file}</span> : <CrNcMissing />}
                                {r.index != null && <span className="cr-nc-kv-note">{crNnT(t, 'crNrEntry', { n: r.index + 1 })}</span>}
                            </span>
                        )}
                    </td>
                    <td className="cr-nv-acts-cell">
                        <CrButton className="cr-btn-xs" onClick={onFlip} disabled={readOnly || busy || noSwitch} data-cr-nr-flip={r.key}
                            title={noSwitch ? t('crNrAbsentNoSwitch') : undefined} aria-describedby={noSwitch ? CR_NR_WHY_ID : undefined}>
                            {waits ? t('crNrUndo') : r.enabled ? t('disable') : t('enable')}
                        </CrButton>
                    </td>
                </tr>
            );
        }

        // repos: the list the view read (data.repos), fail a refused or failed read. A switch waits
        // here until Save; Save sends each one through the view's handler, one after the other
        function CrNodeRepos({ node, repos, fail, loading, saving, readOnly, onToggle, onAptUpdate, onReload, onDirty }) {
            const { t } = useTranslation();
            const [pending, setPending] = useState({});
            const [busy, setBusy] = useState(false);
            const [apt, setApt] = useState(false);
            const alive = useRef(true);
            useEffect(() => () => { alive.current = false; }, []);
            useEffect(() => { setPending({}); }, [node]);
            const m = useMemo(() => crNrModel(repos), [repos]);
            // pending keeps the state each switch asks for (true enabled), taken when it was clicked; one
            // the node already has (a switch that went through and was read again) is not waiting
            const has = (p, r) => Object.prototype.hasOwnProperty.call(p, r.key) && p[r.key] !== r.enabled;
            const waiting = m.rows.filter(r => has(pending, r));
            useCrNcDirty(onDirty, 'repos', waiting.length > 0);
            const flip = (r) => setPending(p => {
                const next = { ...p };
                if (has(p, r)) delete next[r.key]; else next[r.key] = !r.enabled;
                return next;
            });
            const save = async () => {
                if (busy || !waiting.length) return;
                setBusy(true);
                const left = {};
                for (const r of waiting) {
                    let ok = false;
                    try { ok = await onToggle(r.repo); } catch (e) { ok = false; }
                    if (!ok) left[r.key] = pending[r.key];
                }
                if (!alive.current) return;
                setPending(left);
                setBusy(false);
            };
            const runApt = async () => {
                setApt(true);
                try { await onAptUpdate(); } finally { if (alive.current) setApt(false); }
            };
            const absentWaiting = waiting.filter(r => !r.exists);
            const chanBadge = (r) => {
                if (!r) return null;
                const s = !r.exists ? 'absent' : r.enabled ? 'on' : 'off';
                return <CrBadge tone={s === 'on' ? 'success' : 'neutral'} dot={s === 'on'}>{s === 'absent' ? t('crNrAbsent') : s === 'on' ? t('crNrOn') : t('crNrOff')}</CrBadge>;
            };
            const channelText = { enterprise: 'crNrChanEnt', free: 'crNrChanFree', both: 'crNrChanBoth', none: 'crNrChanNone' }[m.channel];
            // one row group per state, under a heading row like the sensor kinds of the Hardware tab
            const group = (id, title, rows) => (rows.length ? (
                <tbody key={id} data-cr-nc-group={id}>
                    <tr className="cr-nn-grow"><th colSpan={4} scope="rowgroup">{title} <span className="cr-muted">{rows.length}</span></th></tr>
                    {id === 'absent' && (
                        <tr className="cr-nr-why-row"><td colSpan={4}><p className="cr-nc-note cr-muted" id={CR_NR_WHY_ID} data-cr-nr-why="">{t('crNrAbsentNoSwitch')}</p></td></tr>
                    )}
                    {rows.map(r => <CrNrItem key={r.key} r={r} pending={has(pending, r) ? pending[r.key] : undefined} readOnly={readOnly} busy={busy || saving} onFlip={() => flip(r)} />)}
                </tbody>
            ) : null);
            const body = () => {
                if (repos === undefined) {
                    return <CrNcState id="repos" kind={loading ? 'loading' : 'empty'} onRetry={loading ? undefined : onReload}>{loading ? undefined : t('crNcNotRead')}</CrNcState>;
                }
                if (fail) return <CrNcState id="repos" kind="error" onRetry={onReload} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, fail) })}</CrNcState>;
                if (!m.rows.length) return <CrNcState id="repos" kind="empty" onRetry={onReload} retryDisabled={loading}>{t('crNrEmpty')}</CrNcState>;
                return (
                    <>
                        {m.channel !== 'unknown' && (
                            <div className="cr-nv-channel" data-cr-nr-channel={m.channel}>
                                <CrNcKv id="channel" label={t('crNrChannel')} rows={[
                                    m.ent ? { k: 'ent', label: m.ent.name, value: chanBadge(m.ent) } : null,
                                    m.free ? { k: 'free', label: m.free.name, value: chanBadge(m.free) } : null,
                                ]} />
                                <CrNcState id="channel" kind={m.channel === 'both' || m.channel === 'none' ? 'warning' : 'empty'}>{t(channelText)}</CrNcState>
                            </div>
                        )}
                        {m.twice.map(names => (
                            <CrNcState key={names.join('|')} id="repos-twice" kind="warning">{crNnT(t, 'crNrTwice', { names: names.join(', ') })}</CrNcState>
                        ))}
                        {readOnly && <p className="cr-nc-note cr-muted" data-cr-nr-ro="">{t('crNcReadOnly')}</p>}
                        <div className="cr-nn-scroll">
                            <table className="corp-datagrid cr-table cr-nn-table cr-nv-table cr-nr-table" aria-label={t('repositories')}>
                                <thead>
                                    <tr><th>{t('crNrRepo')}</th><th>{t('status')}</th><th>{t('crNrLine')}</th><th aria-label={t('actions')} /></tr>
                                </thead>
                                {group('on', t('crNrOn'), m.groups.on)}
                                {group('off', t('crNrOff'), m.groups.off)}
                                {group('absent', t('crNrAbsentGroup'), m.groups.absent)}
                            </table>
                        </div>
                    </>
                );
            };
            return (
                <CrNcSection id="repos" title={t('repositories')} desc={t('crNrDesc')} editing={waiting.length > 0}
                    badge={m.rows.length ? <span className="cr-muted cr-nn-count">{crNnT(t, 'crNrCount', { on: m.groups.on.length, n: m.rows.length })}</span> : null}
                    actions={(
                        <>
                            <CrNvRefresh id="repos" loading={loading} onClick={onReload} />
                            <span className="cr-nc-acts-sep" aria-hidden="true" />
                            <CrButton icon={<Icons.Download />} onClick={runApt} disabled={readOnly || apt} data-cr-nr-apt="" title={t('crNrAptHint')}>
                                {apt ? t('crNrAptRunning') : t('crNrApt')}
                            </CrButton>
                        </>
                    )}
                    foot={waiting.length > 0 && (
                        <CrNcEditBar id="repos" count={waiting.length} saving={busy || saving} canSave={waiting.length > 0} readOnly={readOnly}
                            note={t('crNrSaveNote')} onCancel={() => setPending({})} onSave={save}>
                            <CrNcChanges id="repos" rows={waiting.map(r => ({ k: r.key, label: r.name,
                                from: r.enabled ? t('crNrOn') : t('crNrOff'), to: pending[r.key] ? t('crNrOn') : t('crNrOff') }))} />
                            {absentWaiting.length > 0 && (
                                <p className="cr-nc-hint cr-nc-hint-warning" data-cr-nc-hint="warning">
                                    {crNnT(t, 'crNrAbsentHint', { names: absentWaiting.map(r => r.name).join(', ') })}
                                </p>
                            )}
                        </CrNcEditBar>
                    )}>
                    {body()}
                </CrNcSection>
            );
        }

        // --- Ceph ---------------------------------------------------------------------------------

        function CrNxList({ id, list, count, loading, onRetry, emptyKey, children }) {
            const { t } = useTranslation();
            if (list.state === 'failed') {
                return <CrNcState id={id} kind="error" onRetry={onRetry} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, list.fail) })}</CrNcState>;
            }
            if (list.state === 'empty') {
                // the status counts some, the list came back without them: that list read failed
                if (count != null && count > 0) return <CrNcState id={id} kind="warning" onRetry={onRetry} retryDisabled={loading}>{crNnT(t, 'crNxListMissing', { n: count })}</CrNcState>;
                return <CrNcState id={id} kind="empty">{t(emptyKey)}</CrNcState>;
            }
            return children;
        }

        // LW Nov 2026 - the Ceph writes of the classic node dialog (NodeModal), same routes, each asked first: set up
        // Ceph on the node, start, stop or restart its services, an OSD in or out, a scrub of one OSD
        function useCrNxOps({ clusterId, node, authFetch, onReload }) {
            const { t } = useTranslation();
            const [ask, setAsk] = useState(null);     // { op, osd } while the question is open
            const [busy, setBusy] = useState(false);
            const [done, setDone] = useState(null);   // { tone, text } of the last write
            const alive = useRef(true);
            useEffect(() => () => { alive.current = false; }, []);
            useEffect(() => { setAsk(null); setDone(null); }, [clusterId, node]);
            const base = `${API_URL}/clusters/${encodeURIComponent(clusterId)}/nodes/${encodeURIComponent(node)}/ceph`;
            const url = (a) => (a.op === 'init' ? `${base}/init` : ['start', 'stop', 'restart'].includes(a.op) ? `${base}/${a.op}`
                : `${base}/osd/${encodeURIComponent(a.osd)}/${a.op}`);
            const run = async () => {
                const a = ask;
                if (!a || busy || !authFetch) return;
                setBusy(true);
                const r = await authFetch(url(a), { method: 'POST', headers: { 'Content-Type': 'application/json' } });
                const body = r ? await r.json().catch(() => null) : null;
                if (!alive.current) return;
                setBusy(false);
                setAsk(null);
                const label = crNxOpLabel(t, a);
                if (r && r.ok) {
                    setDone({ tone: 'success', text: crNnT(t, 'crNxOpDone', { what: label }) });
                    // services take a moment before the status says what they do (the classic dialog waits 2 s)
                    if (['start', 'stop', 'restart'].includes(a.op)) setTimeout(() => { if (alive.current) onReload(); }, 2000);
                    else if (a.op !== 'scrub') onReload();
                } else {
                    const why = body && typeof body.error === 'string' && body.error ? body.error : r ? `HTTP ${r.status}` : t('crNdNoAnswer');
                    setDone({ tone: 'error', text: crNnT(t, 'crNxOpFailed', { what: label, why }) });
                }
            };
            return { ask, setAsk, busy, done, setDone, run };
        }
        function crNxOpLabel(t, a) {
            return crNnT(t, { init: 'crNxOpInit', start: 'crNxOpStart', stop: 'crNxOpStop', restart: 'crNxOpRestart',
                              in: 'crNxOpIn', out: 'crNxOpOut', scrub: 'crNxOpScrub' }[a.op], { osd: a.osd });
        }
        function CrNxOps({ ops, node }) {
            const { t } = useTranslation();
            return (
                <>
                    {ops.done && (
                        <div className={`cr-callout cr-callout-${ops.done.tone}`} role={ops.done.tone === 'error' ? 'alert' : 'status'} data-cr-nx-op-done={ops.done.tone}>
                            {ops.done.tone === 'error' ? <Icons.AlertCircle className="w-4 h-4" /> : <Icons.CheckCircle className="w-4 h-4" />}
                            <div>{ops.done.text}</div>
                            <button type="button" className="cr-btn cr-btn-xs" onClick={() => ops.setDone(null)}>{t('close')}</button>
                        </div>
                    )}
                    {ops.ask && (
                        <CrNcConfirm id={`ceph-${ops.ask.op}`} title={crNnT(t, 'crNxOpAsk', { what: crNxOpLabel(t, ops.ask), node })}
                            goLabel={crNxOpLabel(t, ops.ask)} busy={ops.busy} onCancel={() => { if (!ops.busy) ops.setAsk(null); }} onConfirm={ops.run}>
                            <p>{t({ init: 'crNxOpInitBody', start: 'crNxOpSvcBody', stop: 'crNxOpStopBody', restart: 'crNxOpSvcBody',
                                    in: 'crNxOpInBody', out: 'crNxOpOutBody', scrub: 'crNxOpScrubBody' }[ops.ask.op])}</p>
                        </CrNcConfirm>
                    )}
                </>
            );
        }

        function CrNodeCeph({ clusterId, node, read, loading, onReload, readOnly, authFetch }) {
            const { t } = useTranslation();
            const m = useMemo(() => crNxModel(read), [read]);
            const ops = useCrNxOps({ clusterId, node, authFetch, onReload });
            const may = !readOnly && !!authFetch;
            const refresh = <CrNvRefresh id="ceph" loading={loading} onClick={onReload} />;
            if (m.state !== 'ok') {
                let st;
                if (m.state === 'unread') st = <CrNcState id="ceph" kind={loading ? 'loading' : 'empty'} onRetry={loading ? undefined : onReload}>{loading ? undefined : t('crNcNotRead')}</CrNcState>;
                else if (m.state === 'failed') st = <CrNcState id="ceph" kind="error" onRetry={onReload} retryDisabled={loading}>{crNnT(t, 'crNcReadFailed', { reason: crNdWhy(t, m.fail) })}</CrNcState>;
                // not said as "no Ceph": the same answer comes from a Ceph whose monitors are down
                else if (m.state === 'none') st = <CrNcState id="ceph" kind="warning" onRetry={onReload} retryDisabled={loading}>{t('crNxNone')}</CrNcState>;
                else st = <CrNcState id="ceph" kind="warning" onRetry={onReload} retryDisabled={loading}>{t('crNxBlank')}</CrNcState>;
                return (
                    <CrNcSection id="ceph" data-cr-nx-state={m.state} title="Ceph" desc={t('crNxDesc')} actions={refresh}>
                        {st}
                        {m.state === 'none' && may && (
                            <CrNcDanger id="ceph-init" title={t('crNxOpInit')} desc={t('crNxOpInitDesc')}>
                                <CrButton variant="danger" onClick={() => ops.setAsk({ op: 'init' })} data-cr-nx-op="init">{t('crNxOpInit')}</CrButton>
                            </CrNcDanger>
                        )}
                        <CrNxOps ops={ops} node={node} />
                    </CrNcSection>
                );
            }
            const yes = t('crNxYes'), no = t('crNxNo');
            const inQuorum = (mon) => {
                if (mon.quorum != null) return mon.quorum === true || mon.quorum === 1 || mon.quorum === '1';
                return m.mons.quorum ? m.mons.quorum.includes(String(mon.name)) : null;
            };
            const osdLine = m.osds.total != null ? crNnT(t, 'crNxOsdLine', { up: m.osds.up ?? '?', in: m.osds.in ?? '?', n: m.osds.total }) : null;
            return (
                <>
                    <CrNcSection id="ceph" data-cr-nx-state="ok" title={t('crNxStatus')} desc={t('crNxDesc')}
                        actions={(
                            <>
                                {may && ['start', 'stop', 'restart'].map(op => (
                                    <CrButton key={op} variant={op === 'stop' ? 'danger' : undefined} onClick={() => ops.setAsk({ op })} data-cr-nx-op={op}>
                                        {crNxOpLabel(t, { op })}
                                    </CrButton>
                                ))}
                                {refresh}
                            </>
                        )}
                        badge={<span data-cr-nx-health={m.tone}>{m.status ? <CrBadge tone={m.tone} dot={m.tone !== 'neutral'}>{m.status}</CrBadge> : <CrBadge tone="neutral" dot={false}>{t('crNvHealthNone')}</CrBadge>}</span>}>
                        {m.checks.length > 0 && (
                            <ul className="cr-nv-checks" aria-label={t('crNxChecks')}>
                                {m.checks.map(c => (
                                    <li key={c.name} data-cr-nx-check={c.name}>
                                        <CrBadge tone={CR_NX_TONE[c.severity] || 'neutral'} dot={false}>{c.severity || t('crNsNotReported')}</CrBadge>
                                        <span className="cr-mono">{c.name}</span>
                                        <span>{c.message}</span>
                                        {c.muted && <span className="cr-muted">{t('crNxMuted')}</span>}
                                    </li>
                                ))}
                            </ul>
                        )}
                        <div className="cr-nc-groups">
                            <CrNcGroup id="capacity" title={t('crNxCapacity')}>
                                <CrNcKv id="ceph-capacity" rows={[
                                    { k: 'used', label: t('crNxUsed'), value: <CrNvUsage id="ceph" used={m.bytes.used} total={m.bytes.total} /> },
                                    { k: 'avail', label: t('crNxAvail'), value: crNvBytes(m.bytes.avail) },
                                ]} />
                            </CrNcGroup>
                            <CrNcGroup id="pgs" title={t('crNxPgs')}>
                                <CrNcKv id="ceph-pgs" rows={[
                                    { k: 'pgs', label: t('crNxPgTotal'), value: m.pgs.total },
                                    { k: 'clean', label: t('crNxPgClean'), value: m.pgs.clean },
                                    m.pgs.states.length ? { k: 'states', label: t('crNxPgStates'), value: <span className="cr-nc-chips">{m.pgs.states.map(s => <span key={s.state} className="cr-nn-chip cr-mono">{s.state}: {s.count}</span>)}</span> } : null,
                                ]} />
                            </CrNcGroup>
                            <CrNcGroup id="counts" title={t('crNxDaemons')}>
                                <CrNcKv id="ceph-counts" rows={[
                                    { k: 'osds', label: 'OSDs', value: osdLine },
                                    { k: 'mons', label: t('crNxMons'), value: m.mons.total != null ? crNnT(t, 'crNxMonLine', { n: m.mons.total, q: m.mons.quorum ? m.mons.quorum.length : '?' }) : null },
                                    { k: 'pools', label: t('crNxPools'), value: m.pool.state === 'ok' ? m.pool.rows.length : null, missing: m.pool.state === 'failed' ? t('crNxNotRead') : undefined },
                                ]} />
                            </CrNcGroup>
                        </div>
                    </CrNcSection>
                    <CrNcSection id="ceph-osd" title="OSDs" desc={t('crNxOsdDesc')}
                        badge={osdLine ? <span className="cr-muted cr-nn-count">{osdLine}</span> : null}>
                        <CrNxList id="ceph-osd" list={m.osd} count={m.osds.total} loading={loading} onRetry={onReload} emptyKey="crNxOsdEmpty">
                            <div className="cr-nn-scroll">
                                <table className="corp-datagrid cr-table cr-nn-table" aria-label="OSDs">
                                    <thead><tr><th>{t('name')}</th><th>{t('crNxHost')}</th><th>{t('status')}</th><th>{t('crNxIn')}</th><th>{t('crNxClass')}</th><th>{t('crNxUsed')}</th>{may && <th>{t('actions')}</th>}</tr></thead>
                                    <tbody>
                                        {m.osd.rows.map((o, i) => {
                                            const up = o.status == null ? null : String(o.status).toLowerCase() === 'up';
                                            const isIn = o.in == null ? null : o.in === 1 || o.in === true || o.in === '1';
                                            const pct = crNvNum(o.percent_used);
                                            return (
                                                <tr key={o.name || o.id || i} data-cr-nx-osd={o.name || o.id}>
                                                    <td className="cr-mono">{o.name || (o.id != null ? `osd.${o.id}` : <CrNcMissing />)}</td>
                                                    <td>{o.host || <CrNcMissing />}</td>
                                                    <td>{up == null ? <CrNcMissing /> : <CrBadge tone={up ? 'success' : 'error'}>{String(o.status)}</CrBadge>}</td>
                                                    <td>{isIn == null ? <CrNcMissing /> : isIn ? t('crNxInYes') : <span className="cr-nc-warn">{t('crNxOut')}</span>}</td>
                                                    <td>{o.device_class || <CrNcMissing />}</td>
                                                    <td>{pct != null && pct >= 0 ? (
                                                        <span className={`cr-nv-usage cr-nv-tone-${crStoreTone(pct)}`} data-cr-nv-usage={`osd-${o.name || o.id}`} title={crStoreScale(t)}>
                                                            <span className="cr-nv-bar" aria-hidden="true"><span style={{ width: `${Math.min(100, pct)}%` }} /></span>
                                                            <span className="cr-nv-usage-text">{pct.toFixed(1)}%</span>
                                                        </span>
                                                    ) : <CrNcMissing />}</td>
                                                    {may && (() => {
                                                        const id = o.id != null ? String(o.id) : String(o.name || '').replace(/^osd\./, '');
                                                        if (!id) return <td><CrNcMissing /></td>;
                                                        return (
                                                            <td className="cr-nx-osd-acts">
                                                                {isIn != null && (
                                                                    <button type="button" className="cr-btn cr-btn-xs" onClick={() => ops.setAsk({ op: isIn ? 'out' : 'in', osd: id })}
                                                                        data-cr-nx-op={`${isIn ? 'out' : 'in'}:${id}`}>{isIn ? t('crNxOut') : t('crNxInYes')}</button>
                                                                )}
                                                                <button type="button" className="cr-btn cr-btn-xs" onClick={() => ops.setAsk({ op: 'scrub', osd: id })}
                                                                    data-cr-nx-op={`scrub:${id}`}>{t('crNxScrub')}</button>
                                                            </td>
                                                        );
                                                    })()}
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </CrNxList>
                    </CrNcSection>
                    <CrNxOps ops={ops} node={node} />
                    <CrNcSection id="ceph-mon" title={t('crNxMons')} desc={t('crNxMonDesc')}>
                        <CrNxList id="ceph-mon" list={m.mon} count={m.mons.total} loading={loading} onRetry={onReload} emptyKey="crNxMonEmpty">
                            <div className="cr-nn-scroll">
                                <table className="corp-datagrid cr-table cr-nn-table" aria-label={t('crNxMons')}>
                                    <thead><tr><th>{t('name')}</th><th>{t('crNxHost')}</th><th>{t('crNxAddr')}</th><th>{t('crNxQuorum')}</th></tr></thead>
                                    <tbody>
                                        {m.mon.rows.map((mon, i) => {
                                            const q = inQuorum(mon);
                                            return (
                                                <tr key={mon.name || i} data-cr-nx-mon={mon.name || ''}>
                                                    <td className="cr-mono">{mon.name || <CrNcMissing />}</td>
                                                    <td>{mon.host || <CrNcMissing />}</td>
                                                    <td className="cr-mono">{mon.addr || <CrNcMissing />}</td>
                                                    <td data-cr-nx-quorum={q == null ? 'none' : q ? 'yes' : 'no'}>{q == null ? <CrNcMissing /> : q ? <CrBadge tone="success">{yes}</CrBadge> : <CrBadge tone="warning">{no}</CrBadge>}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </CrNxList>
                    </CrNcSection>
                    <CrNcSection id="ceph-pool" title={t('crNxPools')} desc={t('crNxPoolDesc')}>
                        <CrNxList id="ceph-pool" list={m.pool} count={null} loading={loading} onRetry={onReload} emptyKey="crNxPoolEmpty">
                            <div className="cr-nn-scroll">
                                <table className="corp-datagrid cr-table cr-nn-table" aria-label={t('crNxPools')}>
                                    <thead><tr><th>{t('name')}</th><th>{t('crNxReplicas')}</th><th>{t('crNxPgTotal')}</th><th>{t('crNxApp')}</th><th>{t('crNxStored')}</th><th>{t('crNxUsedPct')}</th></tr></thead>
                                    <tbody>
                                        {m.pool.rows.map((p, i) => {
                                            const size = crNvNum(p.size), min = crNvNum(p.min_size);
                                            const frac = crNvNum(p.percent_used);
                                            const pct = frac != null && frac >= 0 ? Math.min(100, frac * 100) : null;
                                            const apps = p.application_metadata && typeof p.application_metadata === 'object' ? Object.keys(p.application_metadata) : [];
                                            return (
                                                <tr key={p.pool_name || i} data-cr-nx-pool={p.pool_name || ''}>
                                                    <td className="cr-mono">{p.pool_name || <CrNcMissing />}</td>
                                                    <td>{size != null ? (
                                                        <span className={size < 2 ? 'cr-nc-warn' : undefined} data-cr-nx-repl={size}>
                                                            {crNnT(t, 'crNxReplLine', { n: size, min: min != null ? min : '?' })}
                                                        </span>
                                                    ) : <CrNcMissing />}</td>
                                                    <td>{crNvNum(p.pg_num) != null ? crNvNum(p.pg_num) : <CrNcMissing />}</td>
                                                    <td>{apps.length ? apps.join(', ') : <CrNcMissing />}</td>
                                                    <td>{crNvBytes(p.bytes_used) || <CrNcMissing />}</td>
                                                    <td>{pct != null ? (
                                                        <span className={`cr-nv-usage cr-nv-tone-${crStoreTone(pct)}`} data-cr-nv-usage={`pool-${p.pool_name}`} title={crStoreScale(t)}>
                                                            <span className="cr-nv-bar" aria-hidden="true"><span style={{ width: `${pct}%` }} /></span>
                                                            <span className="cr-nv-usage-text">{pct < 0.1 && pct > 0 ? '<0.1%' : `${pct.toFixed(1)}%`}</span>
                                                        </span>
                                                    ) : <CrNcMissing />}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </CrNxList>
                    </CrNcSection>
                </>
            );
        }

        // the storage, repository and Ceph sub tabs of Configure, each from the read the view keeps
        // authFetch: the fetch of CorporateNodeDetailView, for the classic disk writes (round 10)
        function CrNodeStoreCfg({ tab, node, clusterId, data, loading, saving, readOnly, zfsPool, onZfsPool, authFetch,
                                  onReloadDisks, onReloadRepos, onReloadCeph, onToggleRepo, onAptUpdate, onDirty }) {
            const disk = { clusterId, node, read: data.disksRead, loading, onReload: onReloadDisks, authFetch };
            return (
                <div className="cr-nc-page" data-cr-nc-tab={tab}>
                    {tab === 'lvm' && <CrNodeLvm {...disk} />}
                    {tab === 'lvmthin' && <CrNodeLvmThin {...disk} />}
                    {tab === 'zfs' && <CrNodeZfs {...disk} pool={zfsPool} onPool={onZfsPool} />}
                    {tab === 'repos' && <CrNodeRepos node={node} repos={data.reposRead === undefined ? undefined : data.repos} fail={crNdFail(data.reposRead)}
                        loading={loading} saving={saving} readOnly={readOnly} onToggle={onToggleRepo} onAptUpdate={onAptUpdate} onReload={onReloadRepos} onDirty={onDirty} />}
                    {tab === 'ceph' && <CrNodeCeph clusterId={clusterId} node={node} read={data.cephRead} loading={loading} onReload={onReloadCeph}
                        readOnly={readOnly} authFetch={authFetch} />}
                </div>
            );
        }
