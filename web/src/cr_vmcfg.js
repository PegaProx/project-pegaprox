        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned (Preview): the configuration dialog of a QEMU VM - LW Nov 2026
        // ConfigModal (vm_config.js) keeps its state, its fetches and its save; for a QEMU VM in the
        // preview it hands its changes here. What lives in this file: which change applies to the
        // running VM and which waits for the next start (the rules of qemu-server, below), the
        // pending changes panel in place of the footer, what Proxmox VE itself keeps pending after
        // a save, the General tab in sections and the settings without a field. A container keeps
        // the classic dialog, and the classic layouts never reach any of it.
        // ═══════════════════════════════════════════════════════════

        // true inside the dialog of a QEMU VM in the preview: the red restart tags stay out, the
        // panel says it once per change instead
        const CrVcBadgeOff = createContext(false);

        // the classic restart tag of the shared form fields, unchanged where the context is off
        function CrVcRestartBadge({ className, children }) {
            const off = useContext(CrVcBadgeOff);
            if (off) return null;
            return <span className={className}>{children}</span>;
        }

        // --- the restart rules ----------------------------------------------------------------
        // Taken from qemu-server (QemuServer.pm, $fast_plug_option and vmconfig_hotplug_pending):
        // for a running VM PVE writes every change to [PENDING] first, applies what it can live and
        // leaves the rest there until the next start. Line numbers are those of the extracted
        // hotplug_logic.pm (HL) and of QemuServer.pm (QS) at qemu-server HEAD. Older PVE versions
        // can differ; the read of the pending list after a save has the last word.

        // HL 1-14: written to the config at once, whatever runs
        const CR_VC_FAST = ['description', 'hookscript', 'lock', 'migrate_downtime', 'migrate_speed', 'name', 'onboot',
                            'protection', 'shares', 'startup', 'tags', 'vmstatestorage'];
        // HL 16-18 adds every cloud-init option ($confdesc_cloudinit, QS 783-882)
        const CR_VC_CLOUDINIT = ['citype', 'ciuser', 'cipassword', 'ciupgrade', 'cicustom', 'searchdomain', 'nameserver', 'sshkeys'];
        const crVcIsCloudinit = (k) => CR_VC_CLOUDINIT.includes(k) || /^ipconfig\d+$/.test(k);
        // QS 255-264: the default of the hotplug option, and what '1' stands for (QS 1117-1120)
        const CR_VC_HOTPLUG_DEFAULT = 'network,disk,usb';
        // QS 5079-5091: the drive options that never change live on the same volume
        const CR_VC_DRIVE_COLD = ['aio', 'discard', 'iothread', 'queues', 'product', 'cache', 'ssd', 'vendor', 'ro'];
        // QS 5092-5114: the limits that go to the running drive (set_io_throttle), compared as numbers
        const CR_VC_DRIVE_THROTTLE = ['mbps', 'mbps_rd', 'mbps_wr', 'iops', 'iops_rd', 'iops_wr', 'mbps_max', 'mbps_rd_max',
                                      'mbps_wr_max', 'iops_max', 'iops_rd_max', 'iops_wr_max', 'bps_max_length',
                                      'bps_rd_max_length', 'bps_wr_max_length', 'iops_max_length', 'iops_rd_max_length',
                                      'iops_wr_max_length'];
        // the keys of a network device (pve-qm-net); the first part of the classic form is model=macaddr
        const CR_VC_NET_KEYS = ['model', 'macaddr', 'bridge', 'tag', 'trunks', 'firewall', 'link_down', 'rate', 'queues', 'mtu'];
        // HL 135-139 with the hotplug option's own description (QS 262): l26 or Windows newer than 7
        const CR_VC_USB_OS = ['l26', 'win8', 'win10', 'win11'];

        const crVcEmpty = (v) => v === undefined || v === null || v === '';
        const crVcStr = (v) => (crVcEmpty(v) ? '' : String(v));
        // two config values the same for PVE: unset and empty are one, 2 and "2" are one
        const crVcSame = (a, b) => crVcStr(a) === crVcStr(b);
        // safe_num_ne the other way round: both unset, or both set to the same number
        const crVcNumSame = (a, b) => (crVcEmpty(a) || crVcEmpty(b) ? crVcEmpty(a) === crVcEmpty(b) : Number(a) === Number(b));
        // a Perl false: undef, '' and '0' (vmconfig_update_agent tests the raw config value)
        const crVcPerlFalse = (v) => crVcEmpty(v) || String(v) === '0';

        // a property string ("virtio=BC:24:11:AA:BB:CC,bridge=vmbr0"); a part without "=" belongs
        // to the default key
        function crVcProps(value, defaultKey) {
            const out = {};
            crVcStr(value).split(',').forEach(part => {
                if (!part) return;
                const eq = part.indexOf('=');
                if (eq < 0) {
                    if (defaultKey) out[defaultKey] = part;
                    return;
                }
                out[part.slice(0, eq)] = part.slice(eq + 1);
            });
            return out;
        }

        // NET 16-31: the models of a network device, each one also the key of its MAC address (NET 66)
        const CR_VC_NIC_MODELS = ['e1000', 'e1000-82540em', 'e1000-82544gc', 'e1000-82545em', 'e1000e', 'i82551', 'i82557b',
                                  'i82559er', 'ne2k_isa', 'ne2k_pci', 'pcnet', 'rtl8139', 'virtio', 'vmxnet3'];
        const CR_VC_MAC = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i;
        function crVcNet(value) {
            const p = crVcProps(value);
            Object.keys(p).forEach(k => {
                if (!CR_VC_NET_KEYS.includes(k) && (CR_VC_NIC_MODELS.includes(k) || CR_VC_MAC.test(p[k]))) {
                    p.model = k;
                    p.macaddr = p[k];
                    delete p[k];
                }
            });
            return p;
        }

        const crVcDrive = (value) => crVcProps(value, 'file');
        const crVcIsCdrom = (d) => d.media === 'cdrom';
        const crVcIsDrive = (k) => /^(ide|sata|scsi|virtio)\d+$/.test(k) || k === 'efidisk0' || k === 'tpmstate0';

        // the hotplug features the VM runs with (parse_hotplug_features, QS 1112-1129); unset counts
        // as '1' (HL 126-127)
        function crVcHotplug(value) {
            const v = value === undefined || value === null ? '1' : String(value);
            const out = {};
            if (v === '0') return out;
            (v === '1' ? CR_VC_HOTPLUG_DEFAULT : v).split(/[\s,;]+/).filter(Boolean).forEach(f => { out[f] = true; });
            return out;
        }

        // the version a machine type is pinned to ("pc-q35-8.1", "type=pc-i440fx-7.2+pve1,viommu=intel"),
        // null when it is not pinned: then it is the version of the QEMU that started the VM
        function crVcMachineVersion(machine) {
            const p = crVcProps(machine, 'type');
            const m = /-(\d+)\.(\d+)/.exec(p.type || '');
            return m ? [Number(m[1]), Number(m[2])] : null;
        }

        // the disks in the boot order: vm_deviceunplug never unplugs one of them (QS 3963-3964)
        function crVcBootDisks(conf) {
            const boot = crVcProps(conf.boot, 'legacy');
            const out = (boot.order || '').split(';').filter(Boolean);
            if (conf.bootdisk) out.push(String(conf.bootdisk));
            return out;
        }

        const crVcNow = (why, args) => ({ cls: 'now', why, args });
        const crVcRestart = (why, args) => ({ cls: 'restart', why, args });
        const crVcMaybe = (why, args) => ({ cls: 'maybe', why, args });
        const crVcOpen = (why, args) => ({ cls: 'open', why, args });
        // LW Nov 2026 - a live change that still runs on the node (tap_plug, set_io_throttle,
        // change_medium): it applies at once when that works, and stays pending when it dies, so no
        // "applies now" is promised. live: like now, it is no prediction while the pending list is unknown
        const crVcLive = (why, args) => ({ cls: 'maybe', why, args, live: true });
        const crVcNoHot = (feature) => crVcRestart('crVcWhyNoHotplug', { feature });

        // One entry per rule, in the order vmconfig_hotplug_pending tests them. run(key, value, ctx):
        // value undefined is a delete; ctx.conf is the config the VM runs with, ctx.hot its hotplug
        // features, ctx.changes the whole body of the save. dep: the answer reads the running config,
        // so it is no prediction while the pending list is unknown (see crVcClassify).
        // Classes: now (applied at once), restart (waits for the next start), maybe (a hotplug the
        // code can refuse, or a live change the node can fail, then it stays pending), open (not
        // predictable from here).
        const CR_VC_RULES = [
            { id: 'fast-plug', src: 'HL 1-14, 113-120, 188-189', keys: CR_VC_FAST.join(' '),
              match: (k) => CR_VC_FAST.includes(k),
              run: () => crVcNow('crVcWhyFast') },
            { id: 'cloudinit', src: 'HL 16-18, 376-378; QS 783-882', keys: CR_VC_CLOUDINIT.join(' ') + ' ipconfigN',
              match: crVcIsCloudinit,
              run: () => crVcNow('crVcWhyCloudinit') },
            { id: 'cgroup', src: 'HL 207-210, 314-320', keys: 'cpuunits cpulimit',
              match: (k) => k === 'cpuunits' || k === 'cpulimit',
              run: () => crVcNow('crVcWhyCgroup') },
            { id: 'hotplug-option', src: 'HL 150-151, 229-233', keys: 'hotplug', dep: true,
              match: (k) => k === 'hotplug',
              run: (k, v, ctx) => {
                  const cur = crVcStr(ctx.conf.hotplug);
                  const cold = v === undefined ? /(cpu|memory)/.test(cur) : /memory|cpu/.test(crVcStr(v)) || /memory|cpu/.test(cur);
                  return cold ? crVcRestart('crVcWhyHotplugCpuMem') : crVcNow('crVcWhyHotplugOpt');
              } },
            { id: 'tablet', src: 'HL 152-172, 234-254; QS 3857-3870', keys: 'tablet', dep: true,
              match: (k) => k === 'tablet',
              run: (k, v, ctx) => {
                  if (!ctx.hot.usb) return crVcNoHot('usb');
                  // a delete plugs the default back in, the tablet (load_defaults)
                  return v !== undefined && String(v) === '0' ? crVcNow('crVcWhyTabletOff') : crVcMaybe('crVcWhyPlug');
              } },
            { id: 'usb', src: 'HL 131-141, 173-178, 255-263', keys: 'usbN', dep: true,
              match: (k) => /^usb\d+$/.test(k),
              run: (k, v, ctx) => {
                  if (!ctx.hot.usb) return crVcNoHot('usb');
                  const os = crVcStr(ctx.conf.ostype);
                  if (!CR_VC_USB_OS.includes(os)) return crVcRestart('crVcWhyUsbOs', { os: os || '-' });
                  const ver = crVcMachineVersion(ctx.conf.machine);
                  if (!ver) return crVcOpen('crVcWhyUsbMachineOpen');
                  if (ver[0] < 7 || (ver[0] === 7 && ver[1] < 1)) return crVcRestart('crVcWhyUsbMachine', { v: ver.join('.') });
                  return crVcMaybe(v === undefined ? 'crVcWhyUnplug' : 'crVcWhyPlug');
              } },
            { id: 'vcpus', src: 'HL 179-181, 264-266; QS 4246-4300', keys: 'vcpus', dep: true,
              match: (k) => k === 'vcpus',
              run: (k, v, ctx) => {
                  if (!ctx.hot.cpu) return crVcNoHot('cpu');
                  const max = (Number(ctx.conf.sockets) || 1) * (Number(ctx.conf.cores) || 1);
                  if (v !== undefined && Number(v) > max) return crVcRestart('crVcWhyVcpusMax', { max });
                  return crVcMaybe('crVcWhyVcpus');
              } },
            { id: 'balloon', src: 'HL 182-187, 267-279', keys: 'balloon', dep: true,
              match: (k) => k === 'balloon',
              run: (k, v, ctx) => {
                  const cur = ctx.conf.balloon;
                  const was = crVcEmpty(cur) || Number(cur) !== 0;
                  if (v === undefined) return was ? crVcNow('crVcWhyBalloon') : crVcRestart('crVcWhyBalloonToggle');
                  const will = crVcEmpty(v) || Number(v) !== 0;
                  return was !== will ? crVcRestart('crVcWhyBalloonToggle') : crVcNow('crVcWhyBalloon');
              } },
            { id: 'net', src: 'HL 190-198, 280-291; QS 4932-5027', keys: 'netN', dep: true,
              match: (k) => /^net\d+$/.test(k),
              run: (k, v, ctx) => {
                  const hot = !!ctx.hot.network;
                  if (v === undefined) return hot ? crVcMaybe('crVcWhyUnplug') : crVcNoHot('network');
                  if (crVcEmpty(ctx.conf[k])) return hot ? crVcMaybe('crVcWhyPlug') : crVcNoHot('network');
                  const a = crVcNet(ctx.conf[k]);
                  const b = crVcNet(v);
                  const replug = !crVcSame(a.model, b.model) || !crVcSame(a.macaddr, b.macaddr) || !crVcSame(a.queues, b.queues)
                      || !crVcSame(a.mtu, b.mtu) || !(a.bridge && b.bridge);
                  if (replug) return hot ? crVcMaybe('crVcWhyNetReplug') : crVcNoHot('network');
                  return crVcLive('crVcWhyNetLive');
              } },
            // an unused volume is handled by the API before the hotplug step (API2/Qemu.pm, not in the
            // extracted source), so no class is claimed for it
            { id: 'unused', src: 'API2/Qemu.pm (outside the extracted source)', keys: 'unusedN',
              match: (k) => /^unused\d+$/.test(k),
              run: () => crVcOpen('crVcWhyUnused') },
            { id: 'efi-tpm', src: 'HL 199-201, 293', keys: 'efidisk0 tpmstate0',
              match: (k) => k === 'efidisk0' || k === 'tpmstate0',
              run: () => crVcRestart('crVcWhyEfiTpm') },
            { id: 'drive', src: 'HL 199-203, 292-310; QS 5054-5162, 3957-3964', keys: 'ideN sataN scsiN virtioN', dep: true,
              match: crVcIsDrive,
              run: (k, v, ctx) => {
                  const hot = !!ctx.hot.disk;
                  const ideSata = /^(ide|sata)\d+$/.test(k);
                  const boot = crVcBootDisks(ctx.conf).includes(k);
                  if (v === undefined) {
                      if (ideSata) return crVcRestart('crVcWhyIdeSata');
                      if (!hot) return crVcNoHot('disk');
                      return boot ? crVcRestart('crVcWhyBootDisk') : crVcMaybe('crVcWhyUnplug');
                  }
                  const nd = crVcDrive(v);
                  if (!crVcEmpty(ctx.conf[k])) {
                      const od = crVcDrive(ctx.conf[k]);
                      if ((nd.media || 'disk') !== (od.media || 'disk')) return crVcRestart('crVcWhyMedia');
                      if (crVcIsCdrom(od)) return crVcLive('crVcWhyCdrom');
                      if (!crVcSame(nd.file, od.file)) {
                          if (!hot) return crVcNoHot('disk');
                          return boot ? crVcRestart('crVcWhyBootDisk') : crVcMaybe('crVcWhyUnplug');
                      }
                      if (CR_VC_DRIVE_COLD.some(o => !crVcSame(nd[o], od[o]))) return crVcRestart('crVcWhyDiskCold');
                      if (CR_VC_DRIVE_THROTTLE.some(o => !crVcNumSame(nd[o], od[o]))) return crVcLive('crVcWhyDiskLive');
                      return crVcNow('crVcWhyDiskWritten');
                  }
                  if (!hot) return crVcNoHot('disk');
                  if (ideSata) return crVcRestart('crVcWhyIdeSata');
                  return crVcMaybe('crVcWhyPlug');
              } },
            { id: 'memory', src: 'HL 204-206, 311-313 (conditions in Memory.pm)', keys: 'memory', dep: true,
              match: (k) => k === 'memory',
              run: (k, v, ctx) => (ctx.hot.memory ? crVcMaybe('crVcWhyMemory') : crVcNoHot('memory')) },
            { id: 'agent', src: 'HL 321-322; QS 5031-5052', keys: 'agent', dep: true,
              match: (k) => k === 'agent',
              run: (k, v, ctx) => {
                  // a delete is not in the delete branch: skipped (HL 211-212)
                  if (v === undefined || crVcPerlFalse(ctx.conf.agent)) return crVcRestart('crVcWhyAgent');
                  const a = crVcProps(ctx.conf.agent, 'enabled');
                  const b = crVcProps(v, 'enabled');
                  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
                  keys.delete('fstrim_cloned_disks');
                  for (const o of keys) if (!crVcSame(a[o], b[o])) return crVcRestart('crVcWhyAgent');
                  return crVcNow('crVcWhyAgentLive');
              } },
            { id: 'not-hotpluggable', src: 'HL 211-212, 323-325', keys: '*',
              match: () => true,
              run: () => crVcRestart('crVcWhyNotHot') },
        ];

        // A key that already waits, set back to what the VM runs with (or a key that only waits to be
        // added, deleted again): update_vm writes it, then cleanup_pending drops the waiting entry
        // (pve-guest-common AbstractConfig.pm 139-170; API2/Qemu.pm 2617-2622) and nothing is left
        // for the hotplug step
        function crVcCancels(key, value, pending) {
            const p = (pending || []).find(x => x && x.key === key);
            if (!p) return false;
            if (value === undefined) return !('value' in p);
            return 'value' in p && crVcSame(p.value, value);
        }

        // What a change does to the VM: {cls, rule, why, args}. ctx: running (the VM runs), conf (the
        // config it runs with), changes (the body), pendingKnown (the pending list was read), pending
        // (its rows).
        function crVcClassify(key, value, ctx) {
            if (!ctx || !ctx.running) return { cls: 'next', rule: 'stopped', why: 'crVcWhyStopped' };
            if (ctx.pendingKnown && crVcCancels(key, value, ctx.pending)) return { cls: 'now', rule: 'cancels-pending', why: 'crVcWhyCancels' };
            const conf = ctx.conf || {};
            const full = { ...ctx, conf, changes: ctx.changes || {}, hot: crVcHotplug(conf.hotplug) };
            const rule = CR_VC_RULES.find(r => r.match(key));
            const out = { ...rule.run(key, value, full), rule: rule.id };
            // the running value is a guess while the pending list is unknown: "now" is not promised then
            if (rule.dep && !ctx.pendingKnown && (out.cls === 'now' || out.live)) return { cls: 'open', rule: rule.id, why: 'crVcWhyPendingUnknown' };
            return out;
        }

        // the classification table, for whoever has to check it against qemu-server
        window.PegaProxVmCfgRules = Object.freeze({
            classify: crVcClassify,
            // tested before the table, with the pending list
            before: [{ id: 'cancels-pending', src: 'AbstractConfig.pm 139-170 (cleanup_pending); API2/Qemu.pm 2617-2622', keys: 'a key that waits' }],
            rules: CR_VC_RULES.map(r => ({ id: r.id, src: r.src, keys: r.keys })),
        });

        // the config the VM runs with: what GET .../config shows (PVE merges the pending values in),
        // with each key that waits put back to its current value
        function crVcRunning(raw, pending) {
            const conf = { ...(raw || {}) };
            (pending || []).forEach(p => {
                if (!p || !p.key) return;
                if ('value' in p) conf[p.key] = p.value;
                else delete conf[p.key];
            });
            return conf;
        }

        // --- the change tracker ---------------------------------------------------------------

        // the field label of a key, for the panel; a key without a field shows itself
        const CR_VC_LABELS = {
            name: 'name', tags: 'tags', description: 'description', ostype: 'osType', cores: 'crVcCoresPerSocket', sockets: 'sockets',
            cpu: 'crVcLblCpu', memory: 'memory', balloon: 'crVcMinMemory', numa: 'enableNuma', machine: 'machineType',
            scsihw: 'scsiController', onboot: 'startOnBoot', protection: 'protection', agent: 'qemuGuestAgent',
            hotplug: 'hotplug', kvm: 'kvmVirtualization', boot: 'bootOrder', smbios1: 'smbiosSettings',
            vcpus: 'crVcLblVcpus', cpulimit: 'crVcLblCpulimit', cpuunits: 'crVcLblCpuunits', affinity: 'crVcLblAffinity',
            shares: 'crVcLblShares', hugepages: 'crVcLblHugepages', keephugepages: 'crVcLblKeepHuge', audio0: 'crVcLblAudio',
            startup: 'crVcLblStartup',
        };
        const CR_VC_PLAIN_LABELS = { bios: 'BIOS', vga: 'VGA', acpi: 'ACPI' };
        function crVcLabel(t, key) {
            if (CR_VC_PLAIN_LABELS[key]) return CR_VC_PLAIN_LABELS[key];
            const k = CR_VC_LABELS[key];
            const v = k ? t(k) : '';
            return v && v !== k ? v : key;
        }

        // one row per key of the body, the keys of a "delete" list each on its own
        function crVcRows(changes, raw, ctx) {
            const rows = [];
            Object.keys(changes || {}).forEach(key => {
                if (key === 'delete') {
                    crVcStr(changes.delete).split(/[\s,;]+/).filter(Boolean).forEach(k => {
                        rows.push({ key: k, old: (raw || {})[k], del: true, ...crVcClassify(k, undefined, ctx) });
                    });
                    return;
                }
                rows.push({ key, old: (raw || {})[key], value: changes[key], ...crVcClassify(key, changes[key], ctx) });
            });
            return rows;
        }

        // A change to a key that already waits for the next start replaces what waits
        function crVcConflicts(rows, pending) {
            const byKey = {};
            (pending || []).forEach(p => { if (p && p.key) byKey[p.key] = p; });
            // a change back to the running value is no conflict: it takes the waiting one out
            return rows.filter(r => byKey[r.key] && r.rule !== 'cancels-pending').map(r => ({ key: r.key, pending: byKey[r.key] }));
        }

        // Checks against real constraints only, each with the source it rests on. A check returns
        // null or {key, msg, args}
        const CR_VC_DNS_LABEL = '[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?';
        const CR_VC_DNS = new RegExp(`^${CR_VC_DNS_LABEL}(?:\\.${CR_VC_DNS_LABEL})*$`);
        // the tag rule of the classic form (vm_config.js, tag input)
        const CR_VC_TAG = /^[a-z0-9][a-z0-9\-_.+]*$/;
        // QS 360-366: description maxLength 1024 * 8
        const CR_VC_DESC_MAX = 8192;
        const CR_VC_CHECKS = [
            // QS 347-351 format dns-name; the same check as handleSave of the classic form
            (ch) => ('name' in ch && !crVcEmpty(ch.name) && (!CR_VC_DNS.test(String(ch.name)) || String(ch.name).length > 255))
                ? { key: 'name', msg: 'crVcErrName', args: { v: String(ch.name) } } : null,
            (ch) => ('description' in ch && crVcStr(ch.description).length > CR_VC_DESC_MAX)
                ? { key: 'description', msg: 'crVcErrDesc', args: { n: crVcStr(ch.description).length, over: crVcStr(ch.description).length - CR_VC_DESC_MAX } } : null,
        ];
        const crVcCheck = (changes, raw) => [...CR_VC_CHECKS.map(c => c(changes || {})).filter(Boolean), ...crVcCheckHw(changes, raw)];

        // a translation with {placeholders}
        function crVcT(t, key, args) {
            let s = t(key);
            Object.keys(args || {}).forEach(a => { s = s.split(`{${a}}`).join(String(args[a])); });
            return s;
        }

        const CR_VC_FEATURE_NAMES = { network: 'crVcFeatNetwork', disk: 'crVcFeatDisk', usb: 'crVcFeatUsb', cpu: 'crVcFeatCpu', memory: 'crVcFeatMemory' };
        function crVcWhy(t, row) {
            const args = { ...(row.args || {}) };
            if (args.feature) args.feature = t(CR_VC_FEATURE_NAMES[args.feature] || args.feature);
            return crVcT(t, row.why, args);
        }

        const CR_VC_CLASS = {
            now: { label: 'crVcClsNow', tone: 'neutral' },
            next: { label: 'crVcClsNext', tone: 'neutral' },
            maybe: { label: 'crVcClsMaybe', tone: 'neutral' },
            open: { label: 'crVcClsOpen', tone: 'neutral' },
            restart: { label: 'crVcClsRestart', tone: 'warning' },
        };

        // a config value for the panel: unset says so, a long one is cut (the whole one is its title)
        function crVcShow(t, v, key) {
            if (crVcEmpty(v)) return t('crVcNotSet');
            if (key === 'cipassword') return '**********';
            const s = String(v).replace(/\s+/g, ' ');
            return s.length > 60 ? `${s.slice(0, 57)}...` : s;
        }

        // the state of the preview's part of the dialog: the pending list of the VM (read on open and
        // after a save), the review and the answer of PVE after the last save
        function useCrVc({ on, vm, clusterId, authFetch, config, changes, nets }) {
            const [pend, setPend] = useState({ state: 'idle', rows: [] });
            const [open, setOpen] = useState(false);
            const [result, setResult] = useState(null);
            const seq = useRef(0);
            const saving = useRef(false);
            const loaded = !!config;

            const read = async () => {
                const my = ++seq.current;
                setPend(p => ({ ...p, state: 'loading' }));
                let out;
                try {
                    const r = await authFetch(`${API_URL}/clusters/${clusterId}/vms/${vm.node}/qemu/${vm.vmid}/pending`);
                    if (r && r.ok) {
                        const d = await r.json();
                        out = Array.isArray(d && d.pending) ? { state: 'ok', rows: d.pending } : { state: 'error', rows: [], code: r.status };
                    } else if (r) {
                        let d = null;
                        try { d = await r.json(); } catch (e) { d = null; }
                        out = { state: 'error', rows: [], code: r.status, offline: !!(d && d.offline), upstream: d && d.upstream_status };
                    } else {
                        out = { state: 'error', rows: [], code: 0 };
                    }
                } catch (e) {
                    out = { state: 'error', rows: [], code: 0 };
                }
                if (my === seq.current) setPend(out);
                return out;
            };

            useEffect(() => {
                if (on && loaded) read();
            }, [on, loaded, vm.vmid, vm.node, clusterId]);

            const status = (config && config.status && config.status.status) || vm.status;
            const running = status === 'running';
            const raw = (config && config.raw) || {};
            const ctx = {
                running,
                conf: crVcRunning(raw, pend.state === 'ok' ? pend.rows : []),
                changes: changes || {},
                pendingKnown: pend.state === 'ok',
                pending: pend.state === 'ok' ? pend.rows : [],
            };
            // a network device edited on the Network tab: the row shows the interface the backend builds
            const netRows = on && loaded ? Object.keys(nets || {}).sort().map(id => {
                const value = crVcNetBuilt(nets[id], raw[id]);
                return { key: id, old: raw[id], value, net: true, ...crVcClassify(id, value, ctx) };
            }) : [];
            const rows = on && loaded ? [...crVcRows(changes, raw, ctx), ...netRows] : [];
            const issues = on && loaded ? [...crVcCheck(changes, raw), ...crVcCheckNets(nets, raw)] : [];
            const errors = issues.filter(i => !i.note);
            const notes = issues.filter(i => i.note);

            // a device added or removed with its own request (EFI disk, TPM, cloud-init drive, RNG,
            // virtiofs, a disk, its ISO, a network device) reloads the config: what waits for the next
            // start is read again. A drive counts by its volume, so a change of its options saved from
            // the review is read once, by the save
            const devSig = on && loaded ? Object.keys(raw).filter(k => /^(efidisk0|tpmstate0|rng0|virtiofs\d+|hostpci\d+|usb\d+|serial\d+|net\d+|unused\d+|(?:ide|sata|scsi|virtio)\d+)$/.test(k))
                .sort().map(k => `${k}=${/^(ide|sata|scsi|virtio)\d+$/.test(k) ? crVcDrive(raw[k]).file : raw[k]}`).join('|') : null;
            const lastSig = useRef(null);
            useEffect(() => {
                if (devSig === null) return;
                if (lastSig.current !== null && lastSig.current !== devSig && !saving.current) read();
                lastSig.current = devSig;
            }, [devSig]);
            const conflicts = pend.state === 'ok' ? crVcConflicts(rows, pend.rows) : [];

            // after the save: what PVE lists as pending now is the answer, for every key of the body.
            // failed: the keys of the requests that failed; after: the config read after a refused write
            const afterSave = async (sentRows, ok, failed, after) => {
                const base = { ok, rows: sentRows, running, failed: failed || null, after: after || null };
                setResult({ ...base, phase: 'reading' });
                const ans = await read();
                setResult({ ...base, phase: ans.state, pending: ans.rows, code: ans.code, offline: ans.offline, upstream: ans.upstream });
                saving.current = false;
                if (ok) setOpen(false);
            };
            // a save of several requests (network devices, then the config) reads the list once, at its end
            const beginSave = () => { saving.current = true; };

            return { pend, rows, errors, notes, conflicts, open, setOpen, result, setResult, afterSave, beginSave, refresh: read, running, conf: ctx.conf };
        }

        // the classic markdown preview of the description (marked + DOMPurify), escaped text without DOMPurify
        function crVcMarkdown(raw) {
            const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>');
            if (!window.DOMPurify) return esc(raw);
            if (!window.marked) return window.DOMPurify.sanitize(raw);
            return window.DOMPurify.sanitize(window.marked.parse(raw));
        }

        // --- the parts of the dialog ------------------------------------------------------------

        // the mark of a changed field: one neutral sign, what it was, and the way back
        function CrVcMark({ t, row, onRevert }) {
            if (!row) return null;
            return (
                <span className="cr-vc-mark" data-cr-vc-mark={row.key}>
                    <span className="cr-vc-mark-dot" aria-hidden="true"></span>
                    <span title={crVcStr(row.old)}>{crVcT(t, 'crVcWas', { v: crVcShow(t, row.old, row.key) })}</span>
                    <button type="button" className="cr-vc-link" onClick={() => onRevert(row.key)}>{t('crVcRevert')}</button>
                </span>
            );
        }

        function CrVcSection({ title, id, children, aside }) {
            return (
                <section className="cr-vc-sec" data-cr-vc-sec={id}>
                    <header className="cr-vc-sec-head">
                        <h3 className="cr-vc-sec-title">{title}</h3>
                        {aside}
                    </header>
                    <div className="cr-vc-sec-body">{children}</div>
                </section>
            );
        }

        function CrVcField({ label, hint, mark, children, htmlFor, wide, tip }) {
            return (
                <div className={`cr-vc-field${wide ? ' cr-vc-wide' : ''}`}>
                    <div className="cr-vc-label-row">
                        {htmlFor ? <label className="cr-vc-label" htmlFor={htmlFor}>{label}</label> : <span className="cr-vc-label">{label}</span>}
                        {tip}
                        {mark}
                    </div>
                    {children}
                    {hint && <p className="cr-vc-hint">{hint}</p>}
                </div>
            );
        }

        // QS 367-392: the operating system types of PVE, in its own words
        const CR_VC_OS = [['l26', 'crVcOsL26'], ['l24', 'crVcOsL24'], ['win11', 'crVcOsWin11'], ['win10', 'crVcOsWin10'],
                          ['win8', 'crVcOsWin8'], ['win7', 'crVcOsWin7'], ['wvista', 'crVcOsWvista'], ['w2k8', 'crVcOsW2k8'],
                          ['w2k3', 'crVcOsW2k3'], ['w2k', 'crVcOsW2k'], ['wxp', 'crVcOsWxp'], ['solaris', 'crVcOsSolaris'],
                          ['other', 'crVcOsOther']];

        // The General tab: who the VM is, its operating system, tags, description and state
        function CrVcGeneral({ t, vm, config, clusterName, changes, rows, onChange, onRevert, clusterTags, onUnlock }) {
            const raw = config.raw || {};
            const val = (k) => (k in changes ? changes[k] : raw[k]);
            const rowOf = (k) => rows.find(r => r.key === k && !r.del);
            const [tagText, setTagText] = useState('');
            const [tagError, setTagError] = useState('');
            const [suggest, setSuggest] = useState(false);
            const [descEdit, setDescEdit] = useState(false);
            const tags = crVcStr(val('tags')).split(/[;,\s]+/).filter(Boolean);
            const setTags = (list) => onChange('tags', list.join(';'));
            const addTag = (tag) => {
                const v = tag.trim();
                if (!v) return;
                if (!CR_VC_TAG.test(v)) {
                    setTagError(crVcT(t, 'crVcTagBad', { tag: v }));
                    return;
                }
                setTagError('');
                if (!tags.includes(v)) setTags([...tags, v]);
                setTagText('');
            };
            const offered = (clusterTags || []).filter(c => !tags.includes(c.name)
                && (!tagText || c.name.toLowerCase().includes(tagText.toLowerCase())));
            const desc = crVcStr(val('description'));
            const os = crVcStr(val('ostype'));
            const st = config.status || {};
            const lock = config.lock || {};
            const nameErr = (rowOf('name') && crVcCheck({ name: changes.name })[0]) || null;
            const descErr = (rowOf('description') && crVcCheck({ description: changes.description })[0]) || null;

            return (
                <div className="cr-vc-general" data-cr-vc-general="">
                    <div className="cr-vc-cols">
                        <CrVcSection id="identity" title={t('crVcSecIdentity')}>
                                <CrVcField label={t('name')} htmlFor="cr-vc-name" hint={t('crVcNameHint')}
                                    mark={<CrVcMark t={t} row={rowOf('name')} onRevert={onRevert} />}>
                                    <input id="cr-vc-name" className={`cr-input cr-vc-input${nameErr ? ' cr-vc-invalid' : ''}`} value={crVcStr(val('name'))}
                                        onChange={(e) => onChange('name', e.target.value)} spellCheck={false} autoComplete="off"
                                        aria-invalid={nameErr ? 'true' : undefined} />
                                    {nameErr && <p className="cr-vc-error" role="alert">{crVcT(t, nameErr.msg, nameErr.args)}</p>}
                                </CrVcField>
                            <div className="cr-vc-grid">
                                <CrVcField label={t('crVcVmId')}><div className="cr-vc-ro cr-mono" data-cr-vc-ro="vmid">{vm.vmid}</div></CrVcField>
                                <CrVcField label={t('crVcNode')}><div className="cr-vc-ro" data-cr-vc-ro="node">{vm.node}</div></CrVcField>
                                <CrVcField label={t('crVcCluster')}><div className="cr-vc-ro" data-cr-vc-ro="cluster">{clusterName || '-'}</div></CrVcField>
                            </div>
                        </CrVcSection>
                        <CrVcSection id="os" title={t('crVcSecOs')}>
                            <CrVcField label={t('osType')} htmlFor="cr-vc-ostype" hint={t('crVcOsHint')}
                                mark={<CrVcMark t={t} row={rowOf('ostype')} onRevert={onRevert} />}>
                                <select id="cr-vc-ostype" className="cr-select cr-vc-input" value={os} onChange={(e) => onChange('ostype', e.target.value)}>
                                    {!os && <option value="">{t('crVcOsNotSet')}</option>}
                                    {CR_VC_OS.map(([v, k]) => <option key={v} value={v}>{t(k)}</option>)}
                                    {os && !CR_VC_OS.some(([v]) => v === os) && <option value={os}>{os}</option>}
                                </select>
                            </CrVcField>
                            <div className="cr-vc-state" data-cr-vc-state="">
                                <div className="cr-vc-kv"><span>{t('status')}</span>
                                    <strong className={st.status === 'running' ? 'cr-vc-ok' : ''}>{st.status === 'running' ? t('running') : (st.status ? t('stopped') : '-')}</strong></div>
                                <div className="cr-vc-kv"><span>{t('cpuUsage')}</span><strong>{((st.cpu || 0) * 100).toFixed(1)}%</strong></div>
                                <div className="cr-vc-kv"><span>{t('ramUsage')}</span><strong>{((st.mem || 0) / 1073741824).toFixed(1)} GB</strong></div>
                            </div>
                            {lock.locked && (
                                <div className="cr-vc-lock" role="status" data-cr-vc-lock="">
                                    <Icons.AlertTriangle className="w-4 h-4" />
                                    <div className="cr-vc-lock-text">
                                        <strong>{t('vmLocked')}</strong>
                                        <span>{lock.description || lock.reason || 'Locked'}</span>
                                        {lock.unlock_command && <code className="cr-mono">{lock.unlock_command}</code>}
                                    </div>
                                    <button type="button" className="cr-btn" onClick={onUnlock}>{t('unlockVm')}</button>
                                </div>
                            )}
                        </CrVcSection>
                    </div>
                    <CrVcSection id="tags" title={t('tags')} aside={<CrVcMark t={t} row={rowOf('tags')} onRevert={onRevert} />}>
                        <div className="cr-vc-tags" data-cr-vc-tags="">
                            {tags.length === 0 && <span className="cr-vc-muted">{t('crVcTagNone')}</span>}
                            {tags.map(tag => (
                                <span key={tag} className="cr-vc-tag" data-cr-vc-tag={tag}>
                                    {tag}
                                    <button type="button" className="cr-vc-tag-x" aria-label={`${t('crVcTagRemove')} ${tag}`}
                                        onClick={() => setTags(tags.filter(x => x !== tag))}><Icons.X className="w-3 h-3" /></button>
                                </span>
                            ))}
                            <span className="cr-vc-tag-add">
                                <input className="cr-input" value={tagText} placeholder={t('crVcTagAdd')} aria-label={t('crVcTagAdd')}
                                    onChange={(e) => { setTagText(e.target.value); setTagError(''); setSuggest(true); }}
                                    onFocus={() => setSuggest(true)} onBlur={() => setTimeout(() => setSuggest(false), 150)}
                                    onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addTag(tagText); } }} />
                                {suggest && offered.length > 0 && (
                                    <span className="cr-vc-suggest" role="listbox">
                                        {offered.slice(0, 30).map(c => (
                                            <button key={c.name} type="button" role="option" aria-selected="false" className="cr-menu-item"
                                                onMouseDown={(e) => { e.preventDefault(); addTag(c.name); }}>{c.name}</button>
                                        ))}
                                    </span>
                                )}
                            </span>
                        </div>
                        {tagError && <p className="cr-vc-error" role="alert" data-cr-vc-tag-error="">{tagError}</p>}
                    </CrVcSection>
                    <CrVcSection id="description" title={t('description')}
                        aside={<span className="cr-vc-aside">
                            <CrVcMark t={t} row={rowOf('description')} onRevert={onRevert} />
                            <button type="button" className="cr-btn cr-btn-ghost" onClick={() => setDescEdit(!descEdit)}>
                                {descEdit ? t('crVcDescPreview') : t('crVcDescEdit')}</button>
                        </span>}>
                        {descEdit ? (
                            <textarea className={`cr-vc-textarea${descErr ? ' cr-vc-invalid' : ''}`} rows={8} value={desc} aria-label={t('description')}
                                onChange={(e) => onChange('description', e.target.value)} />
                        ) : desc ? (
                            <div className="cr-vc-md md-desc" onClick={() => setDescEdit(true)} dangerouslySetInnerHTML={{ __html: crVcMarkdown(desc) }} />
                        ) : (
                            <button type="button" className="cr-vc-md cr-vc-muted" onClick={() => setDescEdit(true)}>{t('crVcDescEmpty')}</button>
                        )}
                        <div className="cr-vc-count">{crVcT(t, 'crVcDescCount', { n: desc.length, max: CR_VC_DESC_MAX })}</div>
                        {descErr && <p className="cr-vc-error" role="alert">{crVcT(t, descErr.msg, descErr.args)}</p>}
                    </CrVcSection>
                </div>
            );
        }

        // the result of a save as PVE reports it: per key of the body, waiting or in effect
        function CrVcResult({ t, result, onDismiss }) {
            const pend = {};
            (result.pending || []).forEach(p => { if (p && p.key) pend[p.key] = p; });
            const keys = result.rows.map(r => r.key);
            const other = Object.keys(pend).filter(k => !keys.includes(k));
            let summary;
            if (result.phase === 'reading') summary = t('crVcResReading');
            else if (result.phase === 'error') {
                const why = result.offline ? t('crVcOffline') : result.code ? crVcT(t, 'crVcHttp', { code: result.upstream || result.code }) : t('crVcNoAnswer');
                summary = crVcT(t, result.ok ? 'crVcResUnread' : 'crVcResNotSavedUnread', { why });
            } else if (!result.ok) summary = t('crVcResNotSaved');
            else {
                const waiting = keys.filter(k => pend[k]).length;
                summary = waiting === 0
                    ? t(result.running ? 'crVcResAllApplied' : 'crVcResStopped')
                    : crVcT(t, 'crVcResSomePending', { n: waiting, m: keys.length });
            }
            // "not saved" only for a key of a request that failed (a network device: its own key; the
            // config write: every key of its body). PVE writes and applies what it can before it raises
            // the error (API2/Qemu.pm 2641), so such a key counts as saved when the config read after
            // the failure has it as sent
            const failed = new Set(result.failed || (result.ok ? [] : keys));
            const stored = (r) => !!result.after && (r.del ? crVcEmpty(result.after[r.key]) : crVcStoredAs(r.key, result.after[r.key], r.value));
            const verdict = (r) => {
                if (pend[r.key]) return { cls: 'restart', id: 'pending', text: t('crVcResPending') };
                if (failed.has(r.key) && !stored(r)) return { cls: 'neutral', id: 'unsaved', text: t('crVcResNotSavedRow') };
                return { cls: 'neutral', id: 'applied', text: result.running ? t('crVcResApplied') : t('crVcResNextStart') };
            };
            const done = result.phase === 'ok';
            return (
                <div className="cr-vc-result" data-cr-vc-result={result.phase} data-cr-vc-saved={result.ok ? '1' : '0'} role="status">
                    <div className="cr-vc-result-head">
                        <strong>{t('crVcResTitle')}</strong>
                        <span className="cr-vc-result-sum">{summary}</span>
                        <button type="button" className="cr-icon-btn" aria-label={t('crVcDismiss')} onClick={onDismiss}><Icons.X className="w-3.5 h-3.5" /></button>
                    </div>
                    {done && (
                        <ul className="cr-vc-list">
                            {result.rows.map(r => {
                                const v = verdict(r);
                                const differs = (v.cls === 'restart') !== (r.cls === 'restart') && v.id !== 'unsaved';
                                return (
                                    <li key={r.key + (r.del ? ':del' : '')} className="cr-vc-res-row" data-cr-vc-res={r.key} data-cr-vc-verdict={v.id}>
                                        <span className="cr-vc-row-key">{r.key}</span>
                                        <span className={`cr-vc-chip cr-vc-chip-${v.cls === 'restart' ? 'warn' : 'neutral'}`}>{v.text}</span>
                                        {pend[r.key] && 'pending' in pend[r.key] && <span className="cr-vc-row-val cr-mono">-&gt; {crVcShow(t, pend[r.key].pending, r.key)}</span>}
                                        {differs && <span className="cr-vc-muted">{crVcT(t, 'crVcResPredicted', { cls: t(CR_VC_CLASS[r.cls].label) })}</span>}
                                    </li>
                                );
                            })}
                            {other.length > 0 && <li className="cr-vc-muted" data-cr-vc-res-other="">{crVcT(t, 'crVcResOther', { keys: other.join(', ') })}</li>}
                        </ul>
                    )}
                </div>
            );
        }

        // The pending changes panel, in place of the footer: always the count, the review on demand,
        // and the save only from the review
        function CrVcPanel({ t, crv, changesCount, saving, readOnly, onSave, onRevert }) {
            const { rows, errors, conflicts, open, setOpen, result, setResult, pend } = crv;
            const notes = crv.notes || [];
            const n = rows.length;
            const restart = rows.filter(r => r.cls === 'restart').length;
            const canSave = !readOnly && n > 0 && errors.length === 0 && !saving;
            // what already waits for the next start, as PVE lists it, is told on open and not only once an
            // edit touches one of its keys. Warning tone only on a running VM: a stopped one just starts
            const waiting = pend.state === 'ok' ? pend.rows.filter(p => p && p.key) : [];
            const [waitOpen, setWaitOpen] = useState(false);
            useEffect(() => { if (changesCount === 0 && open) setOpen(false); }, [changesCount]);
            return (
                <div className="cr-vc-panel" data-cr-vc-panel={open ? 'review' : 'bar'}>
                    {result && <CrVcResult t={t} result={result} onDismiss={() => setResult(null)} />}
                    {open && n > 0 && (
                        <div className="cr-vc-review" data-cr-vc-review="">
                            <ul className="cr-vc-list">
                                {rows.map(r => {
                                    const c = CR_VC_CLASS[r.cls];
                                    return (
                                        <li key={r.key + (r.del ? ':del' : '')} className="cr-vc-row" data-cr-vc-row={r.key} data-cr-vc-class={r.cls} data-cr-vc-rule={r.rule}>
                                            <div className="cr-vc-row-main">
                                                <span className="cr-vc-row-label">{crVcLabel(t, r.key)}</span>
                                                {crVcLabel(t, r.key) !== r.key && <span className="cr-vc-row-key cr-mono">{r.key}</span>}
                                                <span className="cr-vc-row-val cr-mono" title={crVcStr(r.old)}>{crVcShow(t, r.old, r.key)}</span>
                                                <span className="cr-vc-arrow" aria-hidden="true">-&gt;</span>
                                                <span className="cr-vc-row-val cr-vc-new cr-mono" title={r.del ? '' : crVcStr(r.value)}>{r.del ? t('crVcRemoved') : crVcShow(t, r.value, r.key)}</span>
                                                <span className={`cr-vc-chip cr-vc-chip-${c.tone === 'warning' ? 'warn' : 'neutral'}`}>{t(c.label)}</span>
                                                {!r.del && <button type="button" className="cr-vc-link" onClick={() => onRevert(r.key)}>{t('crVcRevert')}</button>}
                                            </div>
                                            <p className="cr-vc-why">{crVcWhy(t, r)}</p>
                                        </li>
                                    );
                                })}
                            </ul>
                            {conflicts.length > 0 && (
                                <div className="cr-vc-block" data-cr-vc-conflicts="">
                                    <strong>{t('crVcConflicts')}</strong>
                                    <ul>{conflicts.map(c => (
                                        <li key={c.key} data-cr-vc-conflict={c.key}>{c.pending.delete
                                            ? crVcT(t, 'crVcConflictDel', { key: c.key })
                                            : crVcT(t, 'crVcConflictPending', { key: c.key, value: crVcShow(t, c.pending.pending, c.key) })}</li>
                                    ))}</ul>
                                </div>
                            )}
                            {notes.length > 0 && (
                                <div className="cr-vc-block" data-cr-vc-notes="">
                                    <strong>{t('crVcNotes')}</strong>
                                    <ul>{notes.map((e, i) => <li key={i} data-cr-vc-note={e.key}>{crVcIssue(t, e)}</li>)}</ul>
                                </div>
                            )}
                            {pend.state === 'error' && <p className="cr-vc-muted" data-cr-vc-pend-unread="">{t('crVcPendUnread')}</p>}
                            <p className="cr-vc-note">{t('crVcNoRestartNote')}</p>
                        </div>
                    )}
                    {waitOpen && waiting.length > 0 && (
                        <div className="cr-vc-block cr-vc-block-wait" data-cr-vc-waiting-list="">
                            <strong>{t('crVcWaitingTitle')}</strong>
                            <ul>{waiting.map(p => (
                                <li key={p.key} className="cr-vc-row-main" data-cr-vc-waiting-row={p.key}>
                                    <span className="cr-vc-row-label">{crVcLabel(t, p.key)}</span>
                                    {crVcLabel(t, p.key) !== p.key && <span className="cr-vc-row-key cr-mono">{p.key}</span>}
                                    <span className="cr-vc-row-val cr-mono">{crVcShow(t, p.value, p.key)}</span>
                                    <span className="cr-vc-arrow" aria-hidden="true">-&gt;</span>
                                    <span className="cr-vc-row-val cr-vc-new cr-mono">{p.delete ? t('crVcRemoved') : crVcShow(t, p.pending, p.key)}</span>
                                </li>
                            ))}</ul>
                        </div>
                    )}
                    {errors.length > 0 && (
                        <div className="cr-vc-block cr-vc-block-error" data-cr-vc-errors="" role="alert">
                            <strong>{t('crVcFixFirst')}</strong>
                            <ul>{errors.map((e, i) => <li key={i} data-cr-vc-error={e.key}>{crVcIssue(t, e)}</li>)}</ul>
                        </div>
                    )}
                    <div className="cr-vc-bar">
                        <div className="cr-vc-sum" data-cr-vc-count={n}>
                            {n === 0 ? <span className="cr-vc-muted">{t('crVcNoChanges')}</span> : (
                                <>
                                    <strong>{n === 1 ? t('crVc1Change') : crVcT(t, 'crVcNChanges', { n })}</strong>
                                    {restart > 0 && <span className="cr-vc-chip cr-vc-chip-warn" data-cr-vc-restart={restart}>
                                        {restart === 1 ? t('crVc1Restart') : crVcT(t, 'crVcNRestart', { n: restart })}</span>}
                                    {errors.length > 0 && <span className="cr-vc-chip cr-vc-chip-error">
                                        {errors.length === 1 ? t('crVc1Problem') : crVcT(t, 'crVcNProblems', { n: errors.length })}</span>}
                                    {notes.length > 0 && <span className="cr-vc-chip" data-cr-vc-notes-count={notes.length}>
                                        {notes.length === 1 ? t('crVc1Note') : crVcT(t, 'crVcNNotes', { n: notes.length })}</span>}
                                </>
                            )}
                            {waiting.length > 0 && (
                                <button type="button" className={`cr-vc-chip cr-vc-chip-${crv.running ? 'warn' : 'neutral'}`} data-cr-vc-waiting={waiting.length}
                                        aria-expanded={waitOpen} onClick={() => setWaitOpen(o => !o)}>
                                    {waiting.length === 1 ? t('crVc1Waiting') : crVcT(t, 'crVcNWaiting', { n: waiting.length })}
                                </button>
                            )}
                            {pend.state === 'error' && <span className="cr-vc-muted" data-cr-vc-pend-unread-bar="">{t('crVcPendUnreadBar')}</span>}
                        </div>
                        <div className="cr-vc-actions">
                            {n > 0 && open && !readOnly && <button type="button" className="cr-btn cr-btn-ghost" onClick={() => onRevert(null)}>{t('crVcDiscardAll')}</button>}
                            {n > 0 && !open && <button type="button" className="cr-btn cr-btn-primary" data-cr-vc-review-open="" onClick={() => setOpen(true)}>{t('crVcReview')}</button>}
                            {n > 0 && open && !readOnly && (
                                <button type="button" className="cr-btn cr-btn-primary" data-cr-vc-save="" disabled={!canSave} onClick={onSave}>
                                    {saving ? <Icons.RotateCw className="w-3.5 h-3.5" /> : <Icons.Save className="w-3.5 h-3.5" />}
                                    {n === 1 ? t('crVcSave1') : crVcT(t, 'crVcSaveN', { n })}
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            );
        }

        // the keys with a field somewhere in this dialog (or a device list); every other key of the
        // config is listed under "Other settings" with its stored value
        const CR_VC_FIELDS = ['name', 'tags', 'description', 'ostype', 'cores', 'sockets', 'cpu', 'vga', 'memory', 'balloon', 'bios',
                              'scsihw', 'machine', 'numa', 'efidisk0', 'tpmstate0', 'rng0', 'onboot', 'protection', 'agent', 'hotplug',
                              'kvm', 'acpi', 'boot', 'bootdisk', 'smbios1', 'lock',
                              // the Hardware tab (round 5, B2)
                              'vcpus', 'cpulimit', 'cpuunits', 'affinity', 'shares', 'hugepages', 'keephugepages', 'audio0',
                              // the Options tab (round 5, B3)
                              'startup'];
        const CR_VC_FIELD_RE = /^(?:(?:ide|sata|scsi|virtio|net|unused|hostpci|usb|serial|virtiofs|numa)\d+)$/;
        // bookkeeping of PVE, not a setting
        const CR_VC_INTERNAL = ['digest'];
        const crVcOtherKeys = (raw) => Object.keys(raw || {})
            .filter(k => !CR_VC_FIELDS.includes(k) && !CR_VC_FIELD_RE.test(k) && !CR_VC_INTERNAL.includes(k)).sort();

        function CrVcOther({ t, config }) {
            const raw = (config && config.raw) || {};
            const keys = crVcOtherKeys(raw);
            const [shut, setShut] = useState(false);
            return (
                <section className="cr-vc-sec cr-vc-other" data-cr-vc-other={keys.length}>
                    <header className="cr-vc-sec-head">
                        <button type="button" className="cr-vc-fold" aria-expanded={!shut} onClick={() => setShut(!shut)}>
                            {shut ? <Icons.ChevronRight className="w-3.5 h-3.5" /> : <Icons.ChevronDown className="w-3.5 h-3.5" />}
                            <h3 className="cr-vc-sec-title">{t('crVcOther')} ({keys.length})</h3>
                        </button>
                    </header>
                    {!shut && (
                        <div className="cr-vc-sec-body">
                            <p className="cr-vc-hint">{keys.length ? t('crVcOtherHint') : t('crVcOtherNone')}</p>
                            {keys.length > 0 && (
                                <dl className="cr-vc-other-list">
                                    {keys.map(k => (
                                        <div key={k} className="cr-vc-other-row" data-cr-vc-other-key={k}>
                                            <dt className="cr-mono">{k}</dt>
                                            <dd className="cr-mono">{k === 'cipassword' ? '**********' : crVcStr(raw[k])}</dd>
                                        </div>
                                    ))}
                                </dl>
                            )}
                        </div>
                    )}
                </section>
            );
        }

        // ═══════════════════════════════════════════════════════════
        // The Hardware tab of a QEMU VM in the preview, in sections - LW Nov 2026
        // CPU, Memory, Firmware & Machine and Additional Hardware. Every field of the classic tab is
        // here, plus the keys the save path passes that it did not offer (vcpus, cpulimit, cpuunits,
        // affinity, shares, hugepages, keephugepages, numaN, audio0). Values go into the same body
        // as the classic form's (crVcPatch, then handleSave of ConfigModal); devices keep their own
        // routes and dialogs. Sources, qemu-server HEAD in cr33/qemu_src: QS = QemuServer.pm,
        // MEM = Memory.pm, CPU = CPUConfig.pm, FLAGS = CPUFlags.pm, MACH = Machine.pm,
        // DRIVE = Drive.pm, OVMF = OVMF.pm, API = API2/Qemu.pm.
        // ═══════════════════════════════════════════════════════════

        const crVcDelList = (changes) => crVcStr((changes || {}).delete).split(/[\s,;]+/).filter(Boolean);

        // the config as it is after the save: the stored one, the body on top, the removed keys out
        function crVcEffective(raw, changes) {
            const eff = { ...(raw || {}) };
            Object.keys(changes || {}).forEach(k => { if (k !== 'delete') eff[k] = changes[k]; });
            crVcDelList(changes).forEach(k => { delete eff[k]; });
            return eff;
        }

        // a value as PVE stores it against the one sent: a network device and a drive by their parts,
        // in any order
        function crVcStoredAs(key, stored, sent) {
            if (crVcSame(stored, sent)) return true;
            if (crVcEmpty(stored) || crVcEmpty(sent)) return false;
            if (/^net\d+$/.test(key)) return crVcSameProps(crVcNet(stored), crVcNet(sent));
            if (crVcIsDrive(key)) return crVcSameProps(crVcDrive(stored), crVcDrive(sent));
            return false;
        }

        // the part of a body the config read after a refused save does not have yet (that read is
        // pending-merged: a key that waits for the next start is stored)
        function crVcUnstored(changes, raw) {
            const next = {};
            Object.keys(changes || {}).forEach(k => {
                if (k !== 'delete' && !crVcStoredAs(k, (raw || {})[k], changes[k])) next[k] = changes[k];
            });
            const del = crVcDelList(changes).filter(k => !crVcEmpty((raw || {})[k]));
            if (del.length) next.delete = del.join(',');
            return next;
        }

        // one edit as the next body: {key: value} sets a key, {key: null} takes it out of the config
        // (the delete list of the same PUT); a value back at the stored one is no change at all
        function crVcPatch(prev, patch, raw) {
            const stored = raw || {};
            const next = { ...(prev || {}) };
            let del = crVcDelList(next);
            Object.keys(patch || {}).forEach(k => {
                const v = patch[k];
                del = del.filter(d => d !== k);
                if (v === null) {
                    delete next[k];
                    if (!crVcEmpty(stored[k])) del.push(k);
                } else if (crVcSame(stored[k], v)) delete next[k];
                else next[k] = v;
            });
            if (del.length) next.delete = del.join(',');
            else delete next.delete;
            return next;
        }

        // a property string from its parts, the default key first and bare like the classic
        // splices write it; empty parts are left out
        function crVcPrint(parts, defaultKey) {
            const out = [];
            if (defaultKey && !crVcEmpty(parts[defaultKey])) out.push(String(parts[defaultKey]));
            Object.keys(parts).forEach(k => {
                if (k !== defaultKey && !crVcEmpty(parts[k])) out.push(`${k}=${parts[k]}`);
            });
            return out.join(',');
        }

        // one part changed the way the classic form changes it: out of the string, back at its end
        function crVcSplice(value, defaultKey, key, v) {
            const p = crVcProps(value, defaultKey);
            delete p[key];
            if (!crVcEmpty(v)) p[key] = String(v);
            return crVcPrint(p, defaultKey);
        }

        // MEM 78-101: memory is "<MiB>" or "current=<MiB>", 512 when unset
        function crVcMemMb(v) {
            if (crVcEmpty(v)) return 512;
            return Number(crVcProps(v, 'current').current);
        }

        // a size for people: whole GiB, else MiB
        function crVcMb(mb) {
            const n = Number(mb);
            if (!Number.isFinite(n)) return '-';
            if (n >= 1024 && n % 1024 === 0) return `${n / 1024} GiB`;
            if (n >= 1024) return `${(n / 1024).toFixed(1)} GiB`;
            return `${Math.round(n)} MiB`;
        }

        // --- CPU ----------------------------------------------------------------------------------

        // FLAGS 19-83: the flags a VM's own CPU settings may carry, grouped for people
        const CR_VC_FLAG_GROUPS = [
            ['crVcFlagGrpSec', ['md-clear', 'pcid', 'spec-ctrl', 'ssbd', 'ibpb', 'virt-ssbd', 'amd-ssbd', 'amd-no-ssb']],
            ['crVcFlagGrpPerf', ['pdpe1gb', 'aes']],
            ['crVcFlagGrpWin', ['hv-tlbflush', 'hv-evmcs']],
            ['crVcFlagGrpVirt', ['nested-virt']],
        ];
        const CR_VC_FLAG_TEXT = {
            'md-clear': 'crVcFlagMdClear', pcid: 'crVcFlagPcid', 'spec-ctrl': 'crVcFlagSpecCtrl', ssbd: 'crVcFlagSsbd',
            ibpb: 'crVcFlagIbpb', 'virt-ssbd': 'crVcFlagVirtSsbd', 'amd-ssbd': 'crVcFlagAmdSsbd', 'amd-no-ssb': 'crVcFlagAmdNoSsb',
            pdpe1gb: 'crVcFlagPdpe1gb', aes: 'crVcFlagAes', 'hv-tlbflush': 'crVcFlagHvTlbflush', 'hv-evmcs': 'crVcFlagHvEvmcs',
            'nested-virt': 'crVcFlagNestedVirt',
        };
        // CPU 294-363: the parts of the cpu string this tab has a field for; the rest is kept as is
        const CR_VC_CPU_OWN = ['cputype', 'flags', 'level', 'reported-model'];

        // the flags of a cpu string: 1 on (+), -1 off (-), missing is the model's default
        function crVcFlags(cpu) {
            const out = {};
            crVcStr(crVcProps(cpu, 'cputype').flags).split(';').filter(Boolean).forEach(tk => {
                const m = /^([+-])(.+)$/.exec(tk);
                if (m) out[m[2]] = m[1] === '+' ? 1 : -1;
            });
            return out;
        }

        // one flag set like the classic cycle writes it: its token out of the list, the new one at
        // the end. CPU 469: the string needs a type, so an unset one gets the default type
        function crVcSetFlag(cpu, flag, state, fallbackType) {
            const p = crVcProps(cpu, 'cputype');
            if (crVcEmpty(p.cputype)) p.cputype = fallbackType;
            const toks = crVcStr(p.flags).split(';').filter(Boolean).filter(tk => tk !== `+${flag}` && tk !== `-${flag}`);
            if (state === 1) toks.push(`+${flag}`);
            if (state === -1) toks.push(`-${flag}`);
            delete p.flags;
            if (toks.length) p.flags = toks.join(';');
            return crVcPrint(p, 'cputype');
        }

        // what kind of CPU type it is, for its description and what it means for live migration
        function crVcCpuKind(type) {
            if (!type) return 'default';
            if (type === 'host') return 'host';
            if (type === 'max') return 'max';
            if (/^custom-/.test(type)) return 'custom';
            if (/^x86-64-v\d/.test(type)) return 'level';
            if (/^(kvm|qemu)(32|64)$/.test(type)) return 'generic';
            return 'named';
        }

        // the family of a CPU type for the grouped select. The vendor split is PVE's own
        // (CPUConfig.pm: athlon, phenom, Opteron_G*, EPYC* are AuthenticAMD, the other named x86
        // models GenuineIntel); an aarch64 node lists cortex-*, neoverse-* and a64fx
        const CR_VC_CPU_GROUPS = ['host', 'level', 'generic', 'intel', 'amd', 'arm', 'custom'];
        function crVcCpuGroup(type) {
            const kind = crVcCpuKind(type);
            if (kind === 'host' || kind === 'max') return 'host';
            if (kind === 'level' || kind === 'generic' || kind === 'custom') return kind;
            if (/^(athlon|phenom|Opteron_G\d|EPYC)/.test(type)) return 'amd';
            if (/^(cortex-|neoverse-|a64fx)/.test(type)) return 'arm';
            return 'intel';
        }

        // --- the checks of the Hardware tab ---------------------------------------------------------
        // Each one fires when one of its keys is in the body, so an old problem of the stored config
        // does not block an unrelated change. A check gives {key, msg, args} or a list of them;
        // note: true is a hint that does not block the save.
        const crVcErr = (key, msg, args) => ({ key, msg, args: args || {} });
        const crVcNote = (key, msg, args) => ({ key, msg, args: args || {}, note: true });
        const crVcIsInt = (v) => /^-?\d+$/.test(crVcStr(v).trim());
        const crVcIsNum = (v) => crVcStr(v).trim() !== '' && Number.isFinite(Number(v));
        const crVcNumaKeys = (conf) => Object.keys(conf).filter(k => /^numa\d+$/.test(k)).sort();
        const CR_VC_NUMA_SET = /^\d+(?:-\d+)?(?:;\d+(?:-\d+)?)*$/;
        // a whole number in [min, max] (max null: no upper end); only the value in the body is checked
        function crVcRange(ch, key, min, max, decimals) {
            if (!(key in ch)) return null;
            const v = ch[key];
            const ok = (decimals ? crVcIsNum(v) : crVcIsInt(v)) && Number(v) >= min && (max === null || Number(v) <= max);
            if (ok) return null;
            if (decimals) return crVcErr(key, 'crVcErrNumRange', { min, max });
            return max === null ? crVcErr(key, 'crVcErrMin', { min }) : crVcErr(key, 'crVcErrRange', { min, max });
        }

        // MEM 188-209, 384-389, 500: with memory hotplug the memory is a static base plus modules of
        // 512 MiB (1024 with 1 GiB hugepages), doubling every 32 modules; it has to land on one
        function crVcHotMemSteps(conf) {
            const huge1g = String(conf.hugepages) === '1024';
            const base = 1024 * (huge1g ? (Number(conf.sockets) || 1) : 1);
            let size = huge1g ? 1024 : 512;
            let cur = base;
            const steps = [base];
            for (let j = 0; j < 8; j++) {
                for (let i = 0; i < 32; i++) {
                    cur += size;
                    steps.push(cur);
                }
                size *= 2;
            }
            return { base, steps };
        }

        const CR_VC_HW_CHECKS = [
            // QS 417-430: sockets and cores are whole numbers of at least 1
            { keys: ['sockets'], run: (e, ch) => crVcRange(ch, 'sockets', 1, null) },
            { keys: ['cores'], run: (e, ch) => crVcRange(ch, 'cores', 1, null) },
            // QS 454-459, 4259-4260: vcpus is 1 or more and not above sockets x cores
            { keys: ['vcpus', 'sockets', 'cores'], run: (e, ch) => {
                const r = crVcRange(ch, 'vcpus', 1, null);
                if (r || crVcEmpty(e.vcpus)) return r;
                const max = (Number(e.sockets) || 1) * (Number(e.cores) || 1);
                return Number(e.vcpus) > max ? crVcErr('vcpus', 'crVcErrVcpus', { v: e.vcpus, max }) : null;
            } },
            // QS 279-300
            { keys: ['cpulimit'], run: (e, ch) => crVcRange(ch, 'cpulimit', 0, 128, true) },
            { keys: ['cpuunits'], run: (e, ch) => crVcRange(ch, 'cpuunits', 1, 262144) },
            // QS 730-735: format pve-cpuset, host CPU numbers and ranges
            { keys: ['affinity'], run: (e, ch) => ('affinity' in ch && !/^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/.test(crVcStr(ch.affinity).replace(/\s+/g, '')))
                ? crVcErr('affinity', 'crVcErrAffinity') : null },
            // CPU 352-362 level is 0 to 2^32-1; CPU 498-499 reported-model is refused in a VM's own CPU settings
            { keys: ['cpu'], run: (e, ch) => {
                if (!('cpu' in ch)) return null;
                const p = crVcProps(ch.cpu, 'cputype');
                const out = [];
                if ('level' in p && !(crVcIsInt(p.level) && Number(p.level) >= 0 && Number(p.level) <= 4294967295)) out.push(crVcErr('cpu', 'crVcErrLevel'));
                if (!crVcEmpty(p['reported-model'])) out.push(crVcErr('cpu', 'crVcErrReportedModel'));
                return out;
            } },
            // MEM 78-87: memory at least 16 MiB
            { keys: ['memory'], run: (e, ch) => ('memory' in ch && !(crVcIsInt(ch.memory) && Number(ch.memory) >= 16))
                ? crVcErr('memory', 'crVcErrMin', { min: 16 }) : null },
            // QS 319-326 balloon is 0 or more; API 2283-2292 and not above the memory
            { keys: ['balloon', 'memory'], run: (e, ch) => {
                if ('balloon' in ch && !(crVcIsInt(ch.balloon) && Number(ch.balloon) >= 0)) return crVcErr('balloon', 'crVcErrMin', { min: 0 });
                const m = crVcMemMb(e.memory);
                if (!crVcEmpty(e.balloon) && Number(e.balloon) > 0 && Number.isFinite(m) && Number(e.balloon) > m) {
                    return crVcErr('balloon', 'crVcErrBalloon', { b: e.balloon, m });
                }
                return null;
            } },
            // QS 327-335
            { keys: ['shares'], run: (e, ch) => crVcRange(ch, 'shares', 0, 50000) },
            // MEM 374, 378-380, 384-389, 400-401, 500: what memory hotplug needs at the start
            { keys: ['hotplug', 'numa', 'memory', 'hugepages', 'sockets', /^numa\d+$/], run: (e) => {
                if (!crVcHotplug(e.hotplug).memory) return null;
                const out = [];
                if (String(e.numa) !== '1') out.push(crVcErr('numa', 'crVcErrHotMemNuma'));
                const custom = crVcNumaKeys(e);
                if (custom.length) out.push(crVcErr(custom[0], 'crVcErrHotMemCustomNuma'));
                if (Object.keys(e).some(k => /^virtiofs\d+$/.test(k))) out.push(crVcErr('memory', 'crVcErrHotMemVfs'));
                const m = crVcMemMb(e.memory);
                if (Number.isInteger(m)) {
                    const { base, steps } = crVcHotMemSteps(e);
                    if (m < base) out.push(crVcErr('memory', 'crVcErrHotMemMin', { min: base }));
                    else if (m !== base && m <= steps[steps.length - 1] && !steps.includes(m)) {
                        const lo = steps.filter(s => s < m).pop();
                        const hi = steps.find(s => s > m);
                        out.push(crVcErr('memory', 'crVcErrHotMemAlign', { m, lo, hi }));
                    }
                }
                return out;
            } },
            // MEM 398: hugepages need NUMA
            { keys: ['hugepages', 'numa'], run: (e) => (!crVcEmpty(e.hugepages) && String(e.numa) !== '1')
                ? crVcErr('hugepages', 'crVcErrHugeNuma') : null },
            // MEM 403-460: each NUMA node of its own needs CPUs and memory, host nodes need a policy,
            // hugepages need host nodes, and the nodes add up to the memory
            { keys: [/^numa\d+$/, 'memory', 'hugepages', 'numa'], run: (e, ch) => {
                const keys = crVcNumaKeys(e);
                if (!keys.length) return null;
                if (String(e.numa) !== '1') return crVcNote(keys[0], 'crVcNoteNumaOff', { keys: keys.join(', ') });
                const out = [];
                let sum = 0;
                keys.forEach(k => {
                    const p = crVcProps(e[k]);
                    if (!CR_VC_NUMA_SET.test(crVcStr(p.cpus))) out.push(crVcErr(k, 'crVcErrNumaCpus', { key: k }));
                    if (!crVcIsNum(p.memory) || Number(p.memory) <= 0) out.push(crVcErr(k, 'crVcErrNumaMem', { key: k }));
                    else sum += Number(p.memory);
                    if (!crVcEmpty(p.hostnodes) && !CR_VC_NUMA_SET.test(crVcStr(p.hostnodes))) out.push(crVcErr(k, 'crVcErrNumaHostnodes', { key: k }));
                    if (!crVcEmpty(p.hostnodes) && crVcEmpty(p.policy)) out.push(crVcErr(k, 'crVcErrNumaPolicy', { key: k }));
                    if (crVcEmpty(p.hostnodes) && !crVcEmpty(e.hugepages)) out.push(crVcErr(k, 'crVcErrHugeHostnodes', { key: k }));
                });
                const m = crVcMemMb(e.memory);
                if (!out.length && !crVcHotplug(e.hotplug).memory && Number.isFinite(m) && sum !== m) {
                    out.push(crVcErr(keys[0], 'crVcErrNumaSum', { sum, m }));
                }
                return out;
            } },
            // MACH 136-140: the Intel vIOMMU needs a q35 machine type
            { keys: ['machine'], run: (e) => {
                const p = crVcProps(e.machine, 'type');
                return p.viommu === 'intel' && !/q35/.test(crVcStr(p.type)) ? crVcErr('machine', 'crVcErrViommu') : null;
            } },
            // QS 176-181: VGA memory 4 to 512 MiB
            { keys: ['vga'], run: (e, ch) => {
                if (!('vga' in ch)) return null;
                const p = crVcProps(ch.vga, 'type');
                return 'memory' in p && !(crVcIsInt(p.memory) && Number(p.memory) >= 4 && Number(p.memory) <= 512)
                    ? crVcErr('vga', 'crVcErrVgaMem') : null;
            } },
            // OVMF 145-150: OVMF without an EFI disk starts with a temporary EFI vars disk
            { keys: ['bios'], run: (e) => (e.bios === 'ovmf' && crVcEmpty(e.efidisk0)) ? crVcNote('bios', 'crVcNoteNoEfi') : null },
        ];

        // the checks of the whole dialog: General (above) and Hardware
        function crVcCheckHw(changes, raw) {
            const ch = changes || {};
            const touched = [...Object.keys(ch).filter(k => k !== 'delete'), ...crVcDelList(ch)];
            if (!touched.length) return [];
            const eff = crVcEffective(raw, ch);
            const out = [];
            [...CR_VC_HW_CHECKS, ...CR_VC_TAB_CHECKS].forEach(c => {
                if (!touched.some(k => c.keys.some(p => (p instanceof RegExp ? p.test(k) : p === k)))) return;
                [].concat(c.run(eff, ch) || []).filter(Boolean).forEach(i => out.push(i));
            });
            return out;
        }

        // the text of a problem, with the field it is about
        const crVcIssue = (t, e) => crVcT(t, e.msg, { ...(e.args || {}), field: crVcLabel(t, e.key) });

        // --- the parts of the tab ----------------------------------------------------------------------

        // a help mark beside a technical parameter: the text shows on hover and on keyboard focus
        let crVcTipSeq = 0;
        function CrVcTip({ text, label }) {
            const id = useMemo(() => `cr-vc-tip-${++crVcTipSeq}`, []);
            return (
                <span className="cr-vc-tip">
                    <button type="button" className="cr-vc-tip-btn" aria-label={label} aria-describedby={id}><Icons.Info className="w-3.5 h-3.5" /></button>
                    <span role="tooltip" id={id} className="cr-vc-tip-text">{text}</span>
                </span>
            );
        }

        function CrVcErrors({ t, list }) {
            if (!list || !list.length) return null;
            return list.map((e, i) => <p key={i} className={e.note ? 'cr-vc-hint cr-vc-note-line' : 'cr-vc-error'} role={e.note ? undefined : 'alert'}
                data-cr-vc-field-error={e.key}>{crVcIssue(t, e)}</p>);
        }

        // a collapsible group of advanced options; opens by itself when one of them is changed or wrong
        function CrVcFold({ id, title, count, alert, children }) {
            const [open, setOpen] = useState(false);
            useEffect(() => { if (alert) setOpen(true); }, [alert]);
            return (
                <div className="cr-vc-adv" data-cr-vc-fold={id} data-open={open ? '1' : '0'}>
                    <button type="button" className="cr-vc-fold cr-vc-adv-head" aria-expanded={open} onClick={() => setOpen(!open)}>
                        {open ? <Icons.ChevronDown className="w-3.5 h-3.5" /> : <Icons.ChevronRight className="w-3.5 h-3.5" />}
                        <span>{title}</span>
                        {count > 0 && <span className="cr-vc-chip">{count}</span>}
                    </button>
                    {open && <div className="cr-vc-adv-body">{children}</div>}
                </div>
            );
        }

        // a size in MiB shown in MiB or GiB; the body gets MiB as a number, like the classic field
        function CrVcSize({ id, value, onValue, invalid, disabled, label, placeholder, t }) {
            const mb = Number(value);
            const [unit, setUnit] = useState(Number.isFinite(mb) && mb >= 1024 ? 'GiB' : 'MiB');
            const [draft, setDraft] = useState(null);
            let shown = '';
            if (draft !== null) shown = draft;
            else if (!crVcEmpty(value)) shown = Number.isFinite(mb) ? String(unit === 'GiB' ? Math.round((mb / 1024) * 1000) / 1000 : mb) : String(value);
            const change = (s) => {
                setDraft(s);
                const n = Number(s);
                if (s.trim() === '' || !Number.isFinite(n)) onValue(s.trim());
                else onValue(unit === 'GiB' ? Math.round(n * 1024) : n);
            };
            return (
                <div className="cr-vc-size">
                    <input id={`cr-vc-${id}`} data-cr-vc-input={id} type="number" min="0" step={unit === 'GiB' ? '0.5' : '128'}
                        className={`cr-input cr-vc-input${invalid ? ' cr-vc-invalid' : ''}`} value={shown} disabled={disabled}
                        placeholder={placeholder} aria-invalid={invalid ? 'true' : undefined}
                        onChange={(e) => change(e.target.value)} onBlur={() => setDraft(null)} />
                    <select className="cr-select cr-vc-unit" value={unit} disabled={disabled} aria-label={`${label}: ${t('crVcUnit')}`}
                        data-cr-vc-unit={id} onChange={(e) => { setUnit(e.target.value); setDraft(null); }}>
                        <option value="MiB">MiB</option>
                        <option value="GiB">GiB</option>
                    </select>
                </div>
            );
        }

        // an on/off switch for a 0/1 key
        function CrVcSwitch({ id, checked, onChange, label, disabled }) {
            return (
                <label className="cr-vc-switch" htmlFor={`cr-vc-${id}`}>
                    <input id={`cr-vc-${id}`} data-cr-vc-input={id} type="checkbox" role="switch" checked={!!checked} disabled={disabled}
                        onChange={(e) => onChange(e.target.checked)} />
                    <span className="cr-vc-switch-track" aria-hidden="true"><span className="cr-vc-switch-thumb"></span></span>
                    <span className="cr-vc-switch-label">{label}</span>
                </label>
            );
        }

        // CPU: sockets and cores with the vCPUs they make, the type and what it means for a live
        // migration, the flags by group, NUMA, and the advanced options
        function CrVcCpu({ h, hardwareOptions }) {
            const { t, raw, val, eff, set, num, mark, errOf } = h;
            const sN = crVcEmpty(val('sockets')) ? 1 : Number(val('sockets'));
            const cN = crVcEmpty(val('cores')) ? 1 : Number(val('cores'));
            const total = Number.isInteger(sN) && Number.isInteger(cN) && sN > 0 && cN > 0 ? sN * cN : null;
            const cpu = crVcStr(val('cpu'));
            const cp = crVcProps(cpu, 'cputype');
            const type = cp.cputype || '';
            // CPU 1152-1154: the type of an unset cpu, kvm64 (qemu64 without KVM)
            const fallback = String(eff.kvm) === '0' ? 'qemu64' : 'kvm64';
            const kind = crVcCpuKind(type);
            const flags = crVcFlags(cpu);
            const stored = crVcFlags(raw.cpu);
            const types = [...(hardwareOptions?.cpu_types || ['host', 'kvm64', 'qemu64'])];
            if (type && !types.includes(type)) types.unshift(type);
            const setCpu = (next) => {
                if (crVcEmpty(raw.cpu) && (next === fallback || next === '')) return h.onRevert('cpu');
                return set('cpu', next);
            };
            const setType = (v) => {
                if (!v) return h.onRevert('cpu');
                const p = crVcProps(cpu, 'cputype');
                p.cputype = v;
                return setCpu(crVcPrint(p, 'cputype'));
            };
            const on = Object.keys(flags).filter(f => flags[f] === 1);
            const setCount = Object.keys(flags).length;
            const other = Object.keys(cp).filter(k => !CR_VC_CPU_OWN.includes(k));
            const advKeys = ['vcpus', 'cpulimit', 'cpuunits', 'affinity'];
            const advSet = advKeys.filter(k => !crVcEmpty(val(k))).length + (['level', 'reported-model'].filter(k => !crVcEmpty(cp[k])).length);
            const advAlert = advKeys.some(k => errOf(k).length || h.rowOf(k)) || errOf('cpu').length > 0;
            const totalTxt = total === null ? '-' : String(total);
            return (
                <CrVcSection id="cpu" title={t('crVcSecCpu')}
                    aside={<span className="cr-vc-sec-sum" data-cr-vc-sum="cpu">{crVcT(t, 'crVcCpuSum', { n: totalTxt, type: type || crVcT(t, 'crVcDefaultIs', { v: fallback }) })}</span>}>
                    <div className="cr-vc-hw-cols">
                        <div className="cr-vc-col">
                            <div className="cr-vc-topo" data-cr-vc-topo="">
                                <CrVcField label={t('sockets')} htmlFor="cr-vc-sockets" mark={mark('sockets')}
                                    tip={<CrVcTip label={t('sockets')} text={t('crVcTipSockets')} />}>
                                    <input id="cr-vc-sockets" data-cr-vc-input="sockets" type="number" min="1" step="1"
                                        className={`cr-input cr-vc-input${errOf('sockets').length ? ' cr-vc-invalid' : ''}`}
                                        value={crVcStr(val('sockets'))} placeholder="1" onChange={(e) => num('sockets', e.target.value)} />
                                </CrVcField>
                                <span className="cr-vc-topo-op" aria-hidden="true">×</span>
                                <CrVcField label={t('crVcCoresPerSocket')} htmlFor="cr-vc-cores" mark={mark('cores')}
                                    tip={<CrVcTip label={t('crVcCoresPerSocket')} text={t('crVcTipCores')} />}>
                                    <input id="cr-vc-cores" data-cr-vc-input="cores" type="number" min="1" step="1"
                                        className={`cr-input cr-vc-input${errOf('cores').length ? ' cr-vc-invalid' : ''}`}
                                        value={crVcStr(val('cores'))} placeholder="1" onChange={(e) => num('cores', e.target.value)} />
                                </CrVcField>
                                <span className="cr-vc-topo-op" aria-hidden="true">=</span>
                                <div className="cr-vc-total" data-cr-vc-total={totalTxt}>
                                    <strong>{totalTxt}</strong>
                                    <span>{t('crVcTotalVcpus')}</span>
                                </div>
                            </div>
                            <CrVcErrors t={t} list={[...errOf('sockets'), ...errOf('cores')]} />
                            {!crVcEmpty(val('vcpus')) && total !== null && (
                                <p className="cr-vc-hint" data-cr-vc-vcpus-note="">{crVcT(t, 'crVcVcpusActive', { n: val('vcpus'), max: total })}</p>
                            )}
                            <CrVcField label={t('cpuType')} htmlFor="cr-vc-cputype" mark={mark('cpu')}>
                                <select id="cr-vc-cputype" data-cr-vc-input="cputype" className="cr-select cr-vc-input" value={type} onChange={(e) => setType(e.target.value)}>
                                    {crVcEmpty(raw.cpu) && <option value="">{crVcT(t, 'crVcDefaultIs', { v: fallback })}</option>}
                                    {CR_VC_CPU_GROUPS.map(g => {
                                        const list = types.filter(x => crVcCpuGroup(x) === g);
                                        return list.length > 0 && (
                                            <optgroup key={g} label={t(`crVcCpuGrp_${g}`)} data-cr-vc-cpu-group={g}>
                                                {list.map(x => <option key={x} value={x}>{x}</option>)}
                                            </optgroup>
                                        );
                                    })}
                                </select>
                            </CrVcField>
                            <p className="cr-vc-hint" data-cr-vc-cpu-kind={kind}>{crVcT(t, `crVcCpuKind_${kind}`, { v: fallback })}</p>
                            <CrVcErrors t={t} list={errOf('cpu')} />
                        </div>
                        <div className="cr-vc-col">
                            <div className="cr-vc-callout" data-cr-vc-migration={kind}>
                                <strong>{t('crVcMigTitle')}</strong>
                                <p>{t(`crVcMig_${kind}`)}</p>
                                {kind !== 'host' && <p>{t('crVcMigEnforce')}</p>}
                                {on.length > 0 && <p data-cr-vc-mig-flags="">{crVcT(t, 'crVcMigFlags', { flags: on.map(f => `+${f}`).join(', ') })}</p>}
                            </div>
                            <CrVcField label="NUMA" mark={mark('numa')} tip={<CrVcTip label="NUMA" text={t('crVcTipNuma')} />}>
                                <CrVcSwitch id="numa" checked={String(val('numa')) === '1'} label={String(val('numa')) === '1' ? t('crVcOn') : t('crVcOff')}
                                    onChange={(c) => set('numa', c ? 1 : (crVcEmpty(raw.numa) ? null : 0))} />
                            </CrVcField>
                            <CrVcErrors t={t} list={errOf('numa')} />
                        </div>
                    </div>
                    <div className="cr-vc-group" data-cr-vc-flags="">
                        <div className="cr-vc-group-head">
                            <h4 className="cr-vc-group-title">{t('crVcFlagsTitle')}</h4>
                            <span className="cr-vc-muted" data-cr-vc-flags-sum={setCount}>
                                {setCount ? crVcT(t, 'crVcFlagsSet', { n: setCount }) : t('crVcFlagsNone')}</span>
                        </div>
                        <p className="cr-vc-hint">{t('crVcFlagsHint')}</p>
                        <div className="cr-vc-flag-grid">
                            {CR_VC_FLAG_GROUPS.map(([gk, list]) => (
                                <div className="cr-vc-flag-grp" key={gk} data-cr-vc-flag-grp={gk}>
                                    <div className="cr-vc-flag-grp-title">{t(gk)}</div>
                                    {list.map(f => {
                                        const st = flags[f] || 0;
                                        const was = stored[f] || 0;
                                        const name = st === 1 ? 'on' : st === -1 ? 'off' : 'default';
                                        return (
                                            <div className="cr-vc-flag" key={f} data-cr-vc-flag={f} data-state={name}>
                                                <span className="cr-vc-flag-name cr-mono">
                                                    {st !== was && <span className="cr-vc-mark-dot" title={t('crVcChanged')}></span>}
                                                    {f}
                                                </span>
                                                <CrVcTip label={f} text={t(CR_VC_FLAG_TEXT[f])} />
                                                <span className="cr-vc-seg" role="radiogroup" aria-label={f}>
                                                    {[[0, 'crVcFlagDefault'], [1, 'crVcFlagOn'], [-1, 'crVcFlagOff']].map(([s, k]) => (
                                                        <button key={s} type="button" role="radio" aria-checked={st === s}
                                                            className={`cr-vc-seg-btn${st === s ? ' cr-vc-seg-on' : ''}${st === s && s === -1 ? ' cr-vc-seg-off' : ''}`}
                                                            onClick={() => setCpu(crVcSetFlag(cpu, f, s, fallback))}>{t(k)}</button>
                                                    ))}
                                                </span>
                                            </div>
                                        );
                                    })}
                                </div>
                            ))}
                        </div>
                    </div>
                    <CrVcFold id="cpu-adv" title={t('crVcAdvCpu')} count={advSet} alert={advAlert}>
                        <div className="cr-vc-grid">
                            <CrVcField label={t('crVcLblVcpus')} htmlFor="cr-vc-vcpus" mark={mark('vcpus')}
                                tip={<CrVcTip label={t('crVcLblVcpus')} text={t('crVcTipVcpus')} />}>
                                <input id="cr-vc-vcpus" data-cr-vc-input="vcpus" type="number" min="1" step="1" placeholder={total === null ? '' : crVcT(t, 'crVcAllOf', { n: total })}
                                    className={`cr-input cr-vc-input${errOf('vcpus').length ? ' cr-vc-invalid' : ''}`}
                                    value={crVcStr(val('vcpus'))} onChange={(e) => num('vcpus', e.target.value, true)} />
                                <CrVcErrors t={t} list={errOf('vcpus')} />
                            </CrVcField>
                            <CrVcField label={t('crVcLblCpulimit')} htmlFor="cr-vc-cpulimit" mark={mark('cpulimit')}
                                tip={<CrVcTip label={t('crVcLblCpulimit')} text={t('crVcTipCpulimit')} />}>
                                <input id="cr-vc-cpulimit" data-cr-vc-input="cpulimit" type="number" min="0" max="128" step="0.1" placeholder={t('crVcUnlimited')}
                                    className={`cr-input cr-vc-input${errOf('cpulimit').length ? ' cr-vc-invalid' : ''}`}
                                    value={crVcStr(val('cpulimit'))} onChange={(e) => num('cpulimit', e.target.value, true)} />
                                <CrVcErrors t={t} list={errOf('cpulimit')} />
                            </CrVcField>
                            <CrVcField label={t('crVcLblCpuunits')} htmlFor="cr-vc-cpuunits" mark={mark('cpuunits')}
                                tip={<CrVcTip label={t('crVcLblCpuunits')} text={t('crVcTipCpuunits')} />}>
                                <input id="cr-vc-cpuunits" data-cr-vc-input="cpuunits" type="number" min="1" max="262144" step="1" placeholder={crVcT(t, 'crVcDefaultIs', { v: 100 })}
                                    className={`cr-input cr-vc-input${errOf('cpuunits').length ? ' cr-vc-invalid' : ''}`}
                                    value={crVcStr(val('cpuunits'))} onChange={(e) => num('cpuunits', e.target.value, true)} />
                                <CrVcErrors t={t} list={errOf('cpuunits')} />
                            </CrVcField>
                            <CrVcField label={t('crVcLblAffinity')} htmlFor="cr-vc-affinity" mark={mark('affinity')}
                                tip={<CrVcTip label={t('crVcLblAffinity')} text={t('crVcTipAffinity')} />} hint={t('crVcRootOnly')}>
                                <input id="cr-vc-affinity" data-cr-vc-input="affinity" placeholder={t('crVcAffinityAny')} spellCheck={false}
                                    className={`cr-input cr-vc-input cr-mono${errOf('affinity').length ? ' cr-vc-invalid' : ''}`}
                                    value={crVcStr(val('affinity'))} onChange={(e) => set('affinity', e.target.value.trim() === '' ? null : e.target.value)} />
                                <CrVcErrors t={t} list={errOf('affinity')} />
                            </CrVcField>
                            <CrVcField label="level" htmlFor="cr-vc-level" tip={<CrVcTip label="level" text={t('crVcTipLevel')} />}>
                                <input id="cr-vc-level" data-cr-vc-input="level" type="number" min="0" step="1" placeholder={t('crVcModelDefault')}
                                    className="cr-input cr-vc-input" value={crVcStr(cp.level)}
                                    onChange={(e) => setCpu(crVcSplice(cpu || fallback, 'cputype', 'level', e.target.value.trim()))} />
                            </CrVcField>
                            <CrVcField label="reported-model" htmlFor="cr-vc-reported" tip={<CrVcTip label="reported-model" text={t('crVcTipReported')} />}>
                                <input id="cr-vc-reported" data-cr-vc-input="reported-model" placeholder={t('crVcModelDefault')} spellCheck={false}
                                    className={`cr-input cr-vc-input cr-mono${!crVcEmpty(cp['reported-model']) ? ' cr-vc-invalid' : ''}`} value={crVcStr(cp['reported-model'])}
                                    onChange={(e) => setCpu(crVcSplice(cpu || fallback, 'cputype', 'reported-model', e.target.value.trim()))} />
                            </CrVcField>
                        </div>
                        {other.length > 0 && (
                            <p className="cr-vc-hint" data-cr-vc-cpu-other="">{crVcT(t, 'crVcCpuOther', { parts: other.map(k => `${k}=${cp[k]}`).join(', ') })}</p>
                        )}
                    </CrVcFold>
                </CrVcSection>
            );
        }

        // Memory: the size, ballooning and its minimum with a bar of what is guaranteed and what the
        // host may take back, and the advanced options (shares, hugepages, NUMA nodes)
        function CrVcMemory({ h, status }) {
            const { t, raw, val, eff, set, num, mark, errOf, running } = h;
            const memV = val('memory');
            const mem = crVcMemMb(memV);
            const bV = val('balloon');
            // QS 319-326: unset is on with the target at the memory, 0 is off
            const ballooning = crVcEmpty(bV) || Number(bV) !== 0;
            const minMb = crVcEmpty(bV) ? mem : Number(bV);
            const memOk = Number.isFinite(mem) && mem > 0;
            const minOk = ballooning && Number.isFinite(minMb) && minMb >= 0 && minMb <= mem;
            const used = running && status && status.mem ? status.mem / 1048576 : null;
            const pct = (x) => `${Math.max(0, Math.min(100, (x / mem) * 100)).toFixed(2)}%`;
            const toggle = (c) => {
                if (!c) return set('balloon', 0);
                if (crVcEmpty(raw.balloon) || Number(raw.balloon) !== 0) return h.onRevert('balloon');
                return set('balloon', memOk ? mem : 0);
            };
            const huge = crVcStr(val('hugepages'));
            const advSet = ['shares', 'hugepages', 'keephugepages'].filter(k => !crVcEmpty(val(k))).length + crVcNumaKeys(eff).length;
            const advAlert = ['shares', 'hugepages', 'keephugepages'].some(k => errOf(k).length || h.rowOf(k))
                || Object.keys(h.changes).some(k => /^numa\d+$/.test(k)) || h.errors.some(e => /^numa\d+$/.test(e.key));
            return (
                <CrVcSection id="memory" title={t('crVcSecMemory')}
                    aside={<span className="cr-vc-sec-sum" data-cr-vc-sum="memory">{memOk ? crVcMb(mem) : '-'}</span>}>
                    <div className="cr-vc-hw-cols">
                        <div className="cr-vc-col">
                            <CrVcField label={t('memory')} htmlFor="cr-vc-memory" mark={mark('memory')}
                                tip={<CrVcTip label={t('memory')} text={t('crVcTipMemory')} />}>
                                <CrVcSize id="memory" t={t} label={t('memory')} value={crVcEmpty(memV) ? '' : (Number.isFinite(mem) ? mem : memV)} placeholder="512"
                                    invalid={errOf('memory').length > 0} onValue={(v) => set('memory', v === '' ? '' : v)} />
                                <CrVcErrors t={t} list={errOf('memory')} />
                            </CrVcField>
                            <CrVcField label={t('crVcBallooning')} tip={<CrVcTip label={t('crVcBallooning')} text={t('crVcTipBalloon')} />}>
                                <CrVcSwitch id="ballooning" checked={ballooning} label={ballooning ? t('crVcOn') : t('crVcOff')} onChange={toggle} />
                            </CrVcField>
                            <CrVcField label={t('crVcMinMemory')} htmlFor="cr-vc-balloon" mark={mark('balloon')}
                                hint={!ballooning ? t('crVcMinOff') : crVcEmpty(bV) ? t('crVcMinUnset') : null}>
                                <CrVcSize id="balloon" t={t} label={t('crVcMinMemory')} disabled={!ballooning}
                                    value={!ballooning || crVcEmpty(bV) ? '' : bV} placeholder={memOk ? String(mem) : ''}
                                    invalid={errOf('balloon').length > 0} onValue={(v) => (v === '' ? set('balloon', null) : set('balloon', v))} />
                                <CrVcErrors t={t} list={errOf('balloon')} />
                            </CrVcField>
                        </div>
                        <div className="cr-vc-col">
                            <div className="cr-vc-alloc" data-cr-vc-alloc={ballooning ? 'balloon' : 'fixed'}>
                                <div className="cr-vc-alloc-bar" role="img"
                                    aria-label={memOk ? crVcT(t, ballooning ? 'crVcAllocAria' : 'crVcAllocAriaFixed', { mem: crVcMb(mem), min: crVcMb(minMb) }) : t('crVcAllocNone')}>
                                    {memOk && <span className="cr-vc-alloc-min" style={{ width: ballooning && minOk ? pct(minMb) : '100%' }}></span>}
                                    {memOk && ballooning && minOk && minMb < mem && <span className="cr-vc-alloc-flex" style={{ left: pct(minMb), width: pct(mem - minMb) }}></span>}
                                    {memOk && used !== null && <span className="cr-vc-alloc-used" style={{ left: pct(used) }} title={crVcT(t, 'crVcAllocUsed', { v: crVcMb(used) })}></span>}
                                </div>
                                <div className="cr-vc-alloc-legend">
                                    <span><i className="cr-vc-key cr-vc-key-min"></i>{crVcT(t, ballooning ? 'crVcAllocMin' : 'crVcAllocFixed', { v: crVcMb(ballooning && minOk ? minMb : mem) })}</span>
                                    {ballooning && minOk && minMb < mem && <span><i className="cr-vc-key cr-vc-key-flex"></i>{crVcT(t, 'crVcAllocFlex', { v: crVcMb(mem - minMb) })}</span>}
                                    {used !== null && <span><i className="cr-vc-key cr-vc-key-used"></i>{crVcT(t, 'crVcAllocUsed', { v: crVcMb(used) })}</span>}
                                </div>
                            </div>
                            <p className="cr-vc-hint" data-cr-vc-mem-explain="">{t('crVcMemExplain')}</p>
                        </div>
                    </div>
                    <CrVcFold id="mem-adv" title={t('crVcAdvMemory')} count={advSet} alert={advAlert}>
                        <div className="cr-vc-grid">
                            <CrVcField label={t('crVcLblShares')} htmlFor="cr-vc-shares" mark={mark('shares')}
                                tip={<CrVcTip label={t('crVcLblShares')} text={t('crVcTipShares')} />}>
                                <input id="cr-vc-shares" data-cr-vc-input="shares" type="number" min="0" max="50000" step="1" placeholder={crVcT(t, 'crVcDefaultIs', { v: 1000 })}
                                    className={`cr-input cr-vc-input${errOf('shares').length ? ' cr-vc-invalid' : ''}`}
                                    value={crVcStr(val('shares'))} onChange={(e) => num('shares', e.target.value, true)} />
                                <CrVcErrors t={t} list={errOf('shares')} />
                            </CrVcField>
                            <CrVcField label={t('crVcLblHugepages')} htmlFor="cr-vc-hugepages" mark={mark('hugepages')} hint={t('crVcRootOnly')}
                                tip={<CrVcTip label={t('crVcLblHugepages')} text={t('crVcTipHugepages')} />}>
                                <select id="cr-vc-hugepages" data-cr-vc-input="hugepages" className="cr-select cr-vc-input" value={huge}
                                    onChange={(e) => set('hugepages', e.target.value === '' ? null : e.target.value)}>
                                    <option value="">{t('crVcOff')}</option>
                                    <option value="any">{t('crVcHugeAny')}</option>
                                    <option value="2">2 MiB</option>
                                    <option value="1024">1 GiB</option>
                                </select>
                                <CrVcErrors t={t} list={errOf('hugepages')} />
                            </CrVcField>
                            {(huge || !crVcEmpty(val('keephugepages'))) && (
                                <CrVcField label={t('crVcLblKeepHuge')} mark={mark('keephugepages')} hint={t('crVcRootOnly')}
                                    tip={<CrVcTip label={t('crVcLblKeepHuge')} text={t('crVcTipKeepHuge')} />}>
                                    <CrVcSwitch id="keephugepages" checked={String(val('keephugepages')) === '1'}
                                        label={String(val('keephugepages')) === '1' ? t('crVcOn') : t('crVcOff')}
                                        onChange={(c) => set('keephugepages', c ? 1 : (crVcEmpty(raw.keephugepages) ? null : 0))} />
                                </CrVcField>
                            )}
                        </div>
                        <CrVcNuma h={h} mem={mem} />
                    </CrVcFold>
                </CrVcSection>
            );
        }

        // MEM 22-57, MAX_NUMA 8: the NUMA nodes of the VM's own topology, one numaN key each
        function CrVcNuma({ h, mem }) {
            const { t, val, eff, set, errOf } = h;
            const [extra, setExtra] = useState([]);
            const keys = [...new Set([...crVcNumaKeys(eff), ...extra])].sort((a, b) => Number(a.slice(4)) - Number(b.slice(4)));
            const free = [0, 1, 2, 3, 4, 5, 6, 7].map(i => `numa${i}`).find(k => !keys.includes(k));
            const edit = (k, part, v) => {
                const p = crVcProps(val(k));
                const next = { cpus: p.cpus, memory: p.memory, hostnodes: p.hostnodes, policy: p.policy };
                Object.keys(p).forEach(x => { if (!(x in next)) next[x] = p[x]; });
                next[part] = crVcStr(v).trim();
                const s = crVcPrint(next);
                if (s === '' && crVcEmpty(h.raw[k])) return h.onRevert(k);
                return set(k, s === '' ? null : s);
            };
            const drop = (k) => {
                setExtra(extra.filter(x => x !== k));
                if (crVcEmpty(h.raw[k])) return h.onRevert(k);
                return set(k, null);
            };
            return (
                <div className="cr-vc-group" data-cr-vc-numa={keys.length}>
                    <div className="cr-vc-group-head">
                        <h4 className="cr-vc-group-title">{t('crVcNumaNodes')}</h4>
                        <CrVcTip label={t('crVcNumaNodes')} text={t('crVcTipNumaNodes')} />
                        {free && <button type="button" className="cr-btn cr-btn-ghost cr-vc-group-act" data-cr-vc-numa-add=""
                            onClick={() => setExtra([...extra, free])}><Icons.Plus className="w-3.5 h-3.5" />{t('crVcNumaAdd')}</button>}
                    </div>
                    {keys.length === 0 ? <p className="cr-vc-hint">{crVcT(t, 'crVcNumaNone', { mem: crVcMb(mem) })}</p> : (
                        <div className="cr-vc-numa-list">
                            {keys.map(k => {
                                const p = crVcProps(val(k));
                                return (
                                    <div key={k} className="cr-vc-numa-row" data-cr-vc-numa-row={k}>
                                        <span className="cr-vc-numa-key cr-mono">{k}</span>
                                        <label className="cr-vc-numa-cell"><span>{t('crVcNumaCpus')}</span>
                                            <input className="cr-input cr-vc-input cr-mono" placeholder="0-1" value={crVcStr(p.cpus)} data-cr-vc-input={`${k}.cpus`}
                                                onChange={(e) => edit(k, 'cpus', e.target.value)} /></label>
                                        <label className="cr-vc-numa-cell"><span>{t('crVcNumaMem')}</span>
                                            <input className="cr-input cr-vc-input" type="number" min="1" placeholder="MiB" value={crVcStr(p.memory)} data-cr-vc-input={`${k}.memory`}
                                                onChange={(e) => edit(k, 'memory', e.target.value)} /></label>
                                        <label className="cr-vc-numa-cell"><span>{t('crVcNumaHost')}</span>
                                            <input className="cr-input cr-vc-input cr-mono" placeholder="0" value={crVcStr(p.hostnodes)} data-cr-vc-input={`${k}.hostnodes`}
                                                onChange={(e) => edit(k, 'hostnodes', e.target.value)} /></label>
                                        <label className="cr-vc-numa-cell"><span>{t('crVcNumaPolicy')}</span>
                                            <select className="cr-select cr-vc-input" value={crVcStr(p.policy)} data-cr-vc-input={`${k}.policy`}
                                                onChange={(e) => edit(k, 'policy', e.target.value)}>
                                                <option value="">-</option>
                                                <option value="preferred">preferred</option>
                                                <option value="bind">bind</option>
                                                <option value="interleave">interleave</option>
                                            </select></label>
                                        <button type="button" className="cr-icon-btn" aria-label={`${t('remove')} ${k}`} onClick={() => drop(k)}><Icons.Trash className="w-3.5 h-3.5" /></button>
                                        <div className="cr-vc-numa-err"><CrVcErrors t={t} list={errOf(k)} /></div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            );
        }

        // QS 165-191: the display types of PVE, cirrus is not recommended
        const CR_VC_VGA = [['std', 'crVcVgaStd'], ['virtio', 'crVcVgaVirtio'], ['virtio-gl', 'crVcVgaVirtioGl'], ['qxl', 'crVcVgaQxl'],
                           ['qxl2', 'crVcVgaQxl2'], ['qxl3', 'crVcVgaQxl3'], ['qxl4', 'crVcVgaQxl4'], ['vmware', 'crVcVgaSvga'],
                           ['cirrus', 'crVcVgaCirrus'], ['serial0', 'crVcVgaSerial0'], ['serial1', 'crVcVgaSerial1'],
                           ['serial2', 'crVcVgaSerial2'], ['serial3', 'crVcVgaSerial3'], ['none', 'crVcVgaNone']];
        // QS 353-358: the SCSI controllers, lsi when unset
        const CR_VC_SCSI = [['virtio-scsi-single', 'crVcScsiVirtioSingle'], ['virtio-scsi-pci', 'crVcScsiVirtio'], ['lsi', 'crVcScsiLsi'],
                            ['lsi53c810', 'crVcScsiLsi810'], ['megasas', 'crVcScsiMegasas'], ['pvscsi', 'crVcScsiPvscsi']];
        // QS 210-223: the audio devices and their backends
        const CR_VC_AUDIO = ['ich9-intel-hda', 'intel-hda', 'AC97'];

        // DRIVE 512-530: Secure Boot is on by default with OVMF, an EFI disk of type 4m and the
        // pre-enrolled keys; the guest can still turn it off in its UEFI setup
        function crVcSecureBoot(eff) {
            if (eff.bios !== 'ovmf') return 'nouefi';
            if (crVcEmpty(eff.efidisk0)) return 'noefi';
            const d = crVcDrive(eff.efidisk0);
            if (d.efitype !== '4m') return 'efi2m';
            return String(d['pre-enrolled-keys']) === '1' ? 'on' : 'nokeys';
        }

        // a device of the VM: its key and value, and what Proxmox VE keeps pending for it
        function CrVcDevRow({ t, k, value, extra, pend, onRemove, acts }) {
            return (
                <li className="cr-vc-dev" data-cr-vc-dev={k}>
                    <div className="cr-vc-dev-main">
                        <span className="cr-vc-dev-key cr-mono">{k}</span>
                        <span className="cr-vc-dev-val cr-mono" title={crVcStr(value)}>{crVcStr(value)}</span>
                        {pend && <span className="cr-vc-chip cr-vc-chip-warn" data-cr-vc-dev-pending={k}>{pend.delete ? t('crVcDevRemoveWaits') : t('crVcDevWaits')}</span>}
                        {acts}
                        {onRemove && <button type="button" className="cr-icon-btn" aria-label={`${t('remove')} ${k}`} onClick={onRemove}><Icons.Trash className="w-3.5 h-3.5" /></button>}
                    </div>
                    {extra}
                </li>
            );
        }

        function CrVcDevList({ t, id, title, tip, items, pend, onAdd, addLabel, empty, onRemove }) {
            return (
                <div className="cr-vc-devlist" data-cr-vc-devlist={id}>
                    <div className="cr-vc-group-head">
                        <h4 className="cr-vc-group-title">{title}</h4>
                        {tip}
                        {onAdd && <button type="button" className="cr-btn cr-btn-ghost cr-vc-group-act" data-cr-vc-add={id} onClick={onAdd}>
                            <Icons.Plus className="w-3.5 h-3.5" />{addLabel}</button>}
                    </div>
                    {items.length === 0 ? <p className="cr-vc-muted">{empty}</p> : (
                        <ul className="cr-vc-devs">
                            {items.map(d => <CrVcDevRow key={d.key} t={t} k={d.key} value={d.value} extra={d.extra} pend={pend[d.key]}
                                onRemove={onRemove ? () => onRemove(d.key) : null} />)}
                        </ul>
                    )}
                </div>
            );
        }

        // Firmware & Machine: BIOS or UEFI with Secure Boot, EFI disk and TPM, the machine type with
        // its vIOMMU, the display and the SCSI controller
        function CrVcFirmware({ h, hardwareOptions, dev }) {
            const { t, raw, val, eff, set, mark, errOf, pend } = h;
            const bios = crVcStr(val('bios')) || 'seabios';
            const pickBios = (v) => (crVcEmpty(raw.bios) && v === 'seabios' ? h.onRevert('bios') : set('bios', v));
            const sb = crVcSecureBoot(eff);
            const mach = crVcProps(val('machine'), 'type');
            const mType = crVcStr(mach.type);
            const machOpts = [...(hardwareOptions?.machine_types || [{ value: '', label: t('default') }, { value: 'q35', label: 'q35' }, { value: 'i440fx', label: 'i440fx' }])];
            if (mType && !machOpts.some(o => o.value === mType)) machOpts.push({ value: mType, label: mType });
            const q35 = machOpts.filter(o => /q35/.test(o.value));
            const pc = machOpts.filter(o => o.value && !/q35/.test(o.value));
            // the machine string with one part changed, the other parts kept (viommu, aw-bits, ...)
            const setMachine = (part, v) => {
                const p = crVcProps(val('machine'), 'type');
                if (part === 'type') p.type = v;
                else {
                    delete p[part];
                    if (v) p[part] = v;
                }
                return set('machine', crVcPrint(p, 'type'));
            };
            const ver = crVcMachineVersion(val('machine'));
            const family = /q35/.test(mType) ? 'q35' : 'i440fx';
            const vga = crVcProps(val('vga'), 'type');
            const vgaType = crVcStr(vga.type);
            const setVga = (part, v) => {
                if (part === 'type' && !v) return h.onRevert('vga');
                const p = crVcProps(val('vga'), 'type');
                if (part === 'type') {
                    if (crVcEmpty(p.type) && Object.keys(p).length === 0) return set('vga', v);
                    p.type = v;
                } else {
                    delete p[part];
                    if (!crVcEmpty(v)) p[part] = v;
                }
                const s = crVcPrint(p, 'type');
                return set('vga', s === '' ? null : s);
            };
            const scsi = crVcStr(val('scsihw'));
            const efi = eff.efidisk0;
            const tpm = eff.tpmstate0;
            const advSet = ['viommu', 'aw-bits'].filter(k => !crVcEmpty(mach[k])).length + ['memory', 'clipboard'].filter(k => !crVcEmpty(vga[k])).length;
            const advAlert = errOf('machine').length > 0 || errOf('vga').length > 0;
            return (
                <CrVcSection id="firmware" title={t('crVcSecFirmware')}
                    aside={<span className="cr-vc-sec-sum" data-cr-vc-sum="firmware">{`${bios === 'ovmf' ? 'OVMF (UEFI)' : 'SeaBIOS'} · ${mType || t('default')}`}</span>}>
                    <div className="cr-vc-hw-cols">
                        <div className="cr-vc-col">
                            <CrVcField label={t('crVcFirmwareLbl')} mark={mark('bios')} tip={<CrVcTip label="BIOS" text={t('crVcTipBios')} />}>
                                <div className="cr-vc-choice" role="radiogroup" aria-label={t('crVcFirmwareLbl')} data-cr-vc-input="bios">
                                    {[['seabios', 'SeaBIOS', 'crVcBiosSea'], ['ovmf', 'OVMF (UEFI)', 'crVcBiosOvmf']].map(([v, name, d]) => (
                                        <button key={v} type="button" role="radio" aria-checked={bios === v} data-cr-vc-bios={v}
                                            className={`cr-vc-choice-btn${bios === v ? ' cr-vc-choice-on' : ''}`} onClick={() => pickBios(v)}>
                                            <strong>{name}</strong><span>{t(d)}</span>
                                        </button>
                                    ))}
                                </div>
                            </CrVcField>
                            <CrVcErrors t={t} list={errOf('bios')} />
                            <div className="cr-vc-kvline" data-cr-vc-secureboot={sb}>
                                <span className="cr-vc-kvline-k">{t('crVcSecureBoot')}<CrVcTip label={t('crVcSecureBoot')} text={t('crVcTipSecureBoot')} /></span>
                                <span className={`cr-vc-chip${sb === 'on' ? ' cr-vc-chip-ok' : ''}`}>{t(`crVcSb_${sb}`)}</span>
                            </div>
                            <p className="cr-vc-hint">{t(`crVcSbWhy_${sb}`)}</p>
                            <div className="cr-vc-devlist" data-cr-vc-devlist="efi">
                                <div className="cr-vc-group-head">
                                    <h4 className="cr-vc-group-title">{t('efiDisk')}</h4>
                                    {!efi && bios === 'ovmf' && <button type="button" className="cr-btn cr-btn-ghost cr-vc-group-act" data-cr-vc-add="efi" onClick={dev.onAddEfi}>
                                        <Icons.Plus className="w-3.5 h-3.5" />{t('addEfiDisk')}</button>}
                                </div>
                                {efi ? (
                                    <ul className="cr-vc-devs"><CrVcDevRow t={t} k="efidisk0" value={efi} pend={pend.efidisk0} onRemove={dev.onDeleteEfi} /></ul>
                                ) : <p className="cr-vc-muted">{bios === 'ovmf' ? t('crVcEfiNone') : t('crVcEfiSeabios')}</p>}
                            </div>
                            <div className="cr-vc-devlist" data-cr-vc-devlist="tpm">
                                <div className="cr-vc-group-head">
                                    <h4 className="cr-vc-group-title">{t('tpmChip')}</h4>
                                    <CrVcTip label="TPM" text={t('crVcTipTpm')} />
                                    {!tpm && <button type="button" className="cr-btn cr-btn-ghost cr-vc-group-act" data-cr-vc-add="tpm" onClick={dev.onAddTpm}>
                                        <Icons.Plus className="w-3.5 h-3.5" />{t('addTpm')}</button>}
                                </div>
                                {tpm ? (
                                    <ul className="cr-vc-devs"><CrVcDevRow t={t} k="tpmstate0" value={tpm} pend={pend.tpmstate0} onRemove={dev.onDeleteTpm} /></ul>
                                ) : <p className="cr-vc-muted">{t('crVcTpmNone')}</p>}
                            </div>
                        </div>
                        <div className="cr-vc-col">
                            <CrVcField label={t('machineType')} htmlFor="cr-vc-machine" mark={mark('machine')} tip={<CrVcTip label={t('machineType')} text={t('crVcTipMachine')} />}>
                                <select id="cr-vc-machine" data-cr-vc-input="machine" className={`cr-select cr-vc-input${errOf('machine').length ? ' cr-vc-invalid' : ''}`}
                                    value={mType} onChange={(e) => setMachine('type', e.target.value)}>
                                    <option value="">{t('crVcMachDefault')}</option>
                                    {q35.length > 0 && <optgroup label="q35">{q35.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}</optgroup>}
                                    {pc.length > 0 && <optgroup label="i440fx">{pc.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}</optgroup>}
                                </select>
                            </CrVcField>
                            <p className="cr-vc-hint" data-cr-vc-machine-note="">
                                {t(family === 'q35' ? 'crVcMachQ35' : 'crVcMachPc')} {ver ? crVcT(t, 'crVcMachPinned', { v: ver.join('.') }) : t('crVcMachLatest')}</p>
                            <CrVcErrors t={t} list={errOf('machine')} />
                            <CrVcField label={t('scsiController')} htmlFor="cr-vc-scsihw" mark={mark('scsihw')} tip={<CrVcTip label={t('scsiController')} text={t('crVcTipScsi')} />}>
                                <select id="cr-vc-scsihw" data-cr-vc-input="scsihw" className="cr-select cr-vc-input" value={scsi}
                                    onChange={(e) => (e.target.value === '' ? h.onRevert('scsihw') : set('scsihw', e.target.value))}>
                                    {crVcEmpty(raw.scsihw) && <option value="">{crVcT(t, 'crVcDefaultIs', { v: 'lsi' })}</option>}
                                    {CR_VC_SCSI.map(([v, k]) => <option key={v} value={v}>{`${v} - ${t(k)}`}</option>)}
                                    {scsi && !CR_VC_SCSI.some(([v]) => v === scsi) && <option value={scsi}>{scsi}</option>}
                                </select>
                            </CrVcField>
                            <CrVcField label={t('crVcDisplay')} htmlFor="cr-vc-vga" mark={mark('vga')} tip={<CrVcTip label="VGA" text={t('crVcTipVga')} />}>
                                <select id="cr-vc-vga" data-cr-vc-input="vga" className="cr-select cr-vc-input" value={vgaType} onChange={(e) => setVga('type', e.target.value)}>
                                    {crVcEmpty(raw.vga) && <option value="">{crVcT(t, 'crVcDefaultIs', { v: 'std' })}</option>}
                                    {CR_VC_VGA.map(([v, k]) => <option key={v} value={v}>{t(k)}</option>)}
                                    {vgaType && !CR_VC_VGA.some(([v]) => v === vgaType) && <option value={vgaType}>{vgaType}</option>}
                                </select>
                            </CrVcField>
                        </div>
                    </div>
                    <CrVcFold id="fw-adv" title={t('crVcAdvFirmware')} count={advSet} alert={advAlert}>
                        <div className="cr-vc-grid">
                            <CrVcField label="vIOMMU" htmlFor="cr-vc-viommu" tip={<CrVcTip label="vIOMMU" text={t('crVcTipViommu')} />}>
                                <select id="cr-vc-viommu" data-cr-vc-input="viommu" className="cr-select cr-vc-input" value={crVcStr(mach.viommu)}
                                    onChange={(e) => setMachine('viommu', e.target.value)}>
                                    <option value="">{t('crVcOff')}</option>
                                    <option value="intel">{t('crVcViommuIntel')}</option>
                                    <option value="virtio">VirtIO</option>
                                </select>
                            </CrVcField>
                            <CrVcField label={t('crVcVgaMemory')} htmlFor="cr-vc-vgamem" tip={<CrVcTip label={t('crVcVgaMemory')} text={t('crVcTipVgaMem')} />}>
                                <input id="cr-vc-vgamem" data-cr-vc-input="vga.memory" type="number" min="4" max="512" step="1" placeholder={t('crVcModelDefault')}
                                    className={`cr-input cr-vc-input${errOf('vga').length ? ' cr-vc-invalid' : ''}`} value={crVcStr(vga.memory)}
                                    onChange={(e) => setVga('memory', e.target.value.trim())} />
                            </CrVcField>
                            <CrVcField label={t('crVcClipboard')} htmlFor="cr-vc-clip" tip={<CrVcTip label={t('crVcClipboard')} text={t('crVcTipClipboard')} />}>
                                <select id="cr-vc-clip" data-cr-vc-input="vga.clipboard" className="cr-select cr-vc-input" value={crVcStr(vga.clipboard)}
                                    onChange={(e) => setVga('clipboard', e.target.value)}>
                                    <option value="">{t('crVcClipDefault')}</option>
                                    <option value="vnc">VNC</option>
                                </select>
                            </CrVcField>
                        </div>
                        <CrVcErrors t={t} list={errOf('vga')} />
                    </CrVcFold>
                </CrVcSection>
            );
        }

        // Additional hardware: passthrough devices, serial ports, audio, the cloud-init drive and the
        // classic cards of VirtIO RNG and virtiofs. Devices are added and removed with their own
        // request at once (the classic dialogs); the audio device goes into the review like a field
        function CrVcDevices({ h, dev, rngCard, vfsCard }) {
            const { t, raw, val, set, mark, pend } = h;
            const pt = dev.passthrough || {};
            const ptItems = (kind) => (pt[kind] || []).map(d => ({ key: d.key, value: d.value, extra: dev.ptMappedLine(kind, d) }));
            const audio = crVcProps(val('audio0'));
            const setAudio = (part, v) => {
                if (part === 'device' && !v) return set('audio0', null);
                const p = { device: audio.device || CR_VC_AUDIO[0], driver: audio.driver || 'spice' };
                p[part] = v;
                return set('audio0', crVcPrint(p));
            };
            const ci = Object.entries(raw).filter(([k, v]) => /^(ide|scsi|sata)\d+$/.test(k) && String(v).includes('cloudinit'));
            const count = (pt.usb || []).length + (pt.pci || []).length + (pt.serial || []).length + (audio.device ? 1 : 0) + ci.length
                + (raw.rng0 ? 1 : 0) + Object.keys(raw).filter(k => /^virtiofs\d+$/.test(k)).length;
            return (
                <CrVcSection id="devices" title={t('crVcSecDevices')}
                    aside={<span className="cr-vc-sec-sum" data-cr-vc-sum="devices">{crVcT(t, count === 1 ? 'crVcDev1' : 'crVcDevN', { n: count })}</span>}>
                    <p className="cr-vc-hint cr-vc-dev-note">{t('crVcDevOwnRequest')}</p>
                    <div className="cr-vc-hw-cols">
                        <div className="cr-vc-col">
                            <CrVcDevList t={t} id="usb" title={t('usbDevices')} items={ptItems('usb')} pend={pend} onAdd={() => dev.onAddPassthrough('usb')}
                                addLabel={t('addUsb')} empty={t('noUsbDevices')} onRemove={(k) => dev.onRemovePassthrough('usb', k)}
                                tip={<CrVcTip label={t('usbDevices')} text={t('crVcTipUsb')} />} />
                            <CrVcDevList t={t} id="pci" title={t('pciDevices')} items={ptItems('pci')} pend={pend} onAdd={() => dev.onAddPassthrough('pci')}
                                addLabel={t('addPci')} empty={t('noPciDevices')} onRemove={(k) => dev.onRemovePassthrough('pci', k)}
                                tip={<CrVcTip label={t('pciDevices')} text={t('crVcTipPci')} />} />
                            <CrVcDevList t={t} id="serial" title={t('serialPorts')} items={(pt.serial || []).map(d => ({ key: d.key, value: d.value }))} pend={pend}
                                onAdd={dev.onAddSerial} addLabel={t('addSerial')} empty={t('noSerialPorts')} onRemove={(k) => dev.onRemovePassthrough('serial', k)} />
                        </div>
                        <div className="cr-vc-col">
                            <div className="cr-vc-devlist" data-cr-vc-devlist="audio">
                                <div className="cr-vc-group-head">
                                    <h4 className="cr-vc-group-title">{t('crVcLblAudio')}</h4>
                                    <CrVcTip label={t('crVcLblAudio')} text={t('crVcTipAudio')} />
                                    {mark('audio0')}
                                </div>
                                <div className="cr-vc-grid cr-vc-grid-2">
                                    <CrVcField label={t('crVcAudioDevice')} htmlFor="cr-vc-audio">
                                        <select id="cr-vc-audio" data-cr-vc-input="audio0.device" className="cr-select cr-vc-input" value={crVcStr(audio.device)}
                                            onChange={(e) => setAudio('device', e.target.value)}>
                                            <option value="">{t('crVcNone')}</option>
                                            {CR_VC_AUDIO.map(v => <option key={v} value={v}>{v}</option>)}
                                            {audio.device && !CR_VC_AUDIO.includes(audio.device) && <option value={audio.device}>{audio.device}</option>}
                                        </select>
                                    </CrVcField>
                                    <CrVcField label={t('crVcAudioDriver')} htmlFor="cr-vc-audiodrv">
                                        <select id="cr-vc-audiodrv" data-cr-vc-input="audio0.driver" className="cr-select cr-vc-input" disabled={!audio.device}
                                            value={crVcStr(audio.driver) || 'spice'} onChange={(e) => setAudio('driver', e.target.value)}>
                                            <option value="spice">spice</option>
                                            <option value="none">none</option>
                                        </select>
                                    </CrVcField>
                                </div>
                                {pend.audio0 && <span className="cr-vc-chip cr-vc-chip-warn" data-cr-vc-dev-pending="audio0">{t('crVcDevWaits')}</span>}
                            </div>
                            <CrVcDevList t={t} id="cloudinit" title={t('cloudInitDrive')} items={ci.map(([k, v]) => ({ key: k, value: v }))} pend={pend}
                                onAdd={ci.length ? null : dev.onAddCloudInit} addLabel={t('addCloudInitDrive')} empty={t('noCloudInitDrive')}
                                onRemove={(k) => dev.onDeleteCloudInit(k)} />
                        </div>
                    </div>
                    <div className="cr-vc-slot" data-cr-vc-slot="rng">{rngCard}</div>
                    <div className="cr-vc-slot" data-cr-vc-slot="virtiofs">{vfsCard}</div>
                </CrVcSection>
            );
        }

        // what every tab of the preview works with: the value of a key in the body or the config, the
        // config after the save, the mark and the problems of a key, what waits for the next start
        function crVcTabCtx({ t, config, changes, crv, onSet, onRevert }) {
            const raw = config.raw || {};
            const del = crVcDelList(changes);
            const val = (k) => (k in changes ? changes[k] : (del.includes(k) ? undefined : raw[k]));
            const eff = crVcEffective(raw, changes);
            const rowOf = (k) => crv.rows.find(r => r.key === k);
            const pend = {};
            if (crv.pend.state === 'ok') crv.pend.rows.forEach(p => { if (p && p.key) pend[p.key] = p; });
            const issues = [...crv.errors, ...(crv.notes || [])];
            const set = (k, v) => onSet({ [k]: v });
            return {
                t, raw, val, eff, changes, pend, running: crv.running, errors: crv.errors, rowOf, set, onRevert,
                mark: (k) => <CrVcMark t={t} row={rowOf(k)} onRevert={onRevert} />,
                errOf: (k) => issues.filter(e => e.key === k),
                // a number field: text that is no number stays (the check says what to fix); an optional
                // key emptied leaves the config
                num: (k, s, optional) => {
                    const str = crVcStr(s).trim();
                    if (str === '') return set(k, optional ? null : '');
                    const n = Number(str);
                    return set(k, Number.isFinite(n) ? n : str);
                },
            };
        }

        // The Hardware tab of the preview: four sections over the same changes as the classic tab
        function CrVcHardware({ t, vm, config, changes, crv, hardwareOptions, onSet, onRevert, dev, rngCard, vfsCard }) {
            const h = crVcTabCtx({ t, config, changes, crv, onSet, onRevert });
            return (
                <div className="cr-vc-hw" data-cr-vc-hw="">
                    <CrVcCpu h={h} hardwareOptions={hardwareOptions} />
                    <CrVcMemory h={h} status={config.status} />
                    <CrVcFirmware h={h} hardwareOptions={hardwareOptions} dev={dev} />
                    <CrVcDevices h={h} dev={dev} rngCard={rngCard} vfsCard={vfsCard} />
                </div>
            );
        }

        // the checks and the body edits of the Hardware tab, read only, for whoever has to hold them
        // against the Proxmox VE source
        window.PegaProxVmCfgChecks = Object.freeze({ check: crVcCheck, patch: crVcPatch, setFlag: crVcSetFlag });

        // ═══════════════════════════════════════════════════════════
        // The Disks, Network and Options tabs of a QEMU VM in the preview - LW Nov 2026
        // The same sections, folds and help marks as the Hardware tab. Disks: every device with its
        // storage and size, and the options of an existing volume (cache, discard, SSD emulation, IO
        // thread, backup, AIO, replication, read only) changed in the drive's own string through the
        // review; adding, importing, removing, detaching, resizing, moving, the bus and the ISO keep
        // their classic dialogs and requests. Network: every interface edited in place and saved from
        // the review with the request of the classic edit dialog (PUT .../networks/<id>, one per
        // interface). Options: start and shutdown, boot order, guest agent, hotplug, KVM and ACPI, and
        // the classic SMBIOS card. Sources at qemu-server / pve-common HEAD in cr33/qemu_src:
        // DRIVE = Drive.pm, NET = QemuServer/Network.pm, AGENT = QemuServer/Agent.pm,
        // JS = JSONSchema.pm, QS = QemuServer.pm.
        // ═══════════════════════════════════════════════════════════

        // --- network devices ----------------------------------------------------------------------

        // Python's idea of a false value (None, False, '', 0), which the backend leaves out
        const crVcPyTrue = (v) => !(v === undefined || v === null || v === false || v === '' || v === 0);

        // the interface the backend writes for the edit request: manager.py update_network builds it
        // from these fields, in this order, and keeps the stored parts the dialog does not own
        function crVcNetBuilt(body, stored) {
            const b = body || {};
            const model = b.model === undefined ? 'virtio' : crVcStr(b.model);
            const parts = [crVcPyTrue(b.macaddr) ? `${model}=${b.macaddr}` : model];
            if (crVcPyTrue(b.bridge)) parts.push(`bridge=${b.bridge}`);
            if (crVcPyTrue(b.tag)) parts.push(`tag=${b.tag}`);
            if (crVcPyTrue(b.firewall)) parts.push('firewall=1');
            if (crVcPyTrue(b.rate)) parts.push(`rate=${b.rate}`);
            if (crVcPyTrue(b.queues)) parts.push(`queues=${b.queues}`);
            if (crVcPyTrue(b.mtu)) parts.push(`mtu=${b.mtu}`);
            if (crVcPyTrue(b.link_down)) parts.push('link_down=1');
            return [...parts, ...crVcNetKept(stored)].join(',');
        }

        // the parts of an interface the edit request does not carry (trunks, ...): the backend keeps
        // them as stored (manager.py _net_kept_parts)
        const CR_VC_NET_EDIT = ['model', 'macaddr', 'bridge', 'tag', 'firewall', 'rate', 'queues', 'mtu', 'link_down'];
        function crVcNetKept(value) {
            const p = crVcNet(value);
            return Object.keys(p).filter(k => !CR_VC_NET_EDIT.includes(k) && !crVcEmpty(p[k])).map(k => `${k}=${p[k]}`);
        }

        // NET 48-121 and JS pve_verify_mac_addr (a unicast address), QS 1338-1343 (the start refuses
        // an MTU under 576 other than 1)
        function crVcCheckNets(nets, raw) {
            const out = [];
            Object.keys(nets || {}).sort().forEach(id => {
                const b = nets[id] || {};
                const err = (msg, args) => out.push(crVcErr(id, msg, { key: id, ...(args || {}) }));
                const note = (msg, args) => out.push(crVcNote(id, msg, { key: id, ...(args || {}) }));
                const virtio = crVcStr(b.model || 'virtio') === 'virtio';
                const mac = crVcStr(b.macaddr).trim();
                if (mac && !/^[a-f0-9][02468ace](?::[a-f0-9]{2}){5}$/i.test(mac)) err('crVcErrNetMac', { v: mac, f: 'macaddr' });
                if (!mac) note('crVcNoteNetNewMac', { f: 'macaddr' });
                if (!crVcEmpty(b.tag) && !(crVcIsInt(b.tag) && Number(b.tag) >= 1 && Number(b.tag) <= 4094)) err('crVcErrNetTag', { f: 'tag' });
                if (!crVcEmpty(b.rate) && !(crVcIsNum(b.rate) && Number(b.rate) >= 0)) err('crVcErrNetRate', { f: 'rate' });
                if (!crVcEmpty(b.queues)) {
                    if (!(crVcIsInt(b.queues) && Number(b.queues) >= 0 && Number(b.queues) <= 64)) err('crVcErrNetQueues', { f: 'queues' });
                    else if (Number(b.queues) > 1 && !virtio) note('crVcNoteNetVirtioOnly', { opt: 'queues', f: 'queues' });
                }
                if (!crVcEmpty(b.mtu)) {
                    if (!(crVcIsInt(b.mtu) && Number(b.mtu) >= 1 && Number(b.mtu) <= 65520)) err('crVcErrNetMtu', { f: 'mtu' });
                    else if (!virtio) note('crVcNoteNetVirtioOnly', { opt: 'mtu', f: 'mtu' });
                    else if (Number(b.mtu) !== 1 && Number(b.mtu) < 576) err('crVcErrNetMtuMin', { v: b.mtu, f: 'mtu' });
                }
            });
            return out;
        }

        // --- drives -------------------------------------------------------------------------------------

        const crVcBus = (k) => (/^([a-z]+)\d+$/.exec(k) || [])[1] || k;
        // DRIVE 455-520: the options a bus takes besides the common ones
        const CR_VC_BUS_OPTS = { ide: ['ssd'], sata: ['ssd'], scsi: ['iothread', 'ssd', 'ro'], virtio: ['iothread', 'ro'] };
        const CR_VC_CACHE = ['none', 'writethrough', 'writeback', 'unsafe', 'directsync'];   // DRIVE 193-198
        const CR_VC_AIO = ['native', 'threads', 'io_uring'];                                   // DRIVE 230-235
        // the parts of a drive this tab has a field for; the rest is kept as it is and listed
        const CR_VC_DRIVE_OWN = ['file', 'cache', 'discard', 'ssd', 'iothread', 'backup', 'aio', 'replicate', 'ro', 'size', 'format', 'media'];
        // the classic Disks tab's test for a CD/DVD drive, and its EFI and TPM volumes
        const crVcDiskIsCd = (d) => String(d.value || '').includes('media=cdrom') || d.media === 'cdrom' || (d.volume || '').includes('iso');
        const crVcDiskIsFw = (d) => String(d.id).includes('efidisk') || String(d.id).includes('tpmstate');
        const crVcSameProps = (a, b) => {
            const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
            for (const k of keys) if (!crVcSame(a[k], b[k])) return false;
            return true;
        };

        // JS pve_parse_startup_order: order (also bare), up and down, each a whole number
        const crVcStartupBad = (v) => crVcStr(v).split(',').some(p => p.trim() !== '' && !/^\s*(?:(?:order=)?\d+|up=\d+|down=\d+)\s*$/.test(p));

        const CR_VC_TAB_CHECKS = [
            // DRIVE 455-520: IO thread on SCSI and VirtIO only, SSD emulation not on VirtIO block, read only on SCSI and VirtIO
            { keys: [/^(ide|sata|scsi|virtio)\d+$/], run: (e, ch) => {
                const out = [];
                Object.keys(ch).filter(k => /^(ide|sata|scsi|virtio)\d+$/.test(k)).forEach(k => {
                    const d = crVcDrive(ch[k]);
                    const ok = CR_VC_BUS_OPTS[crVcBus(k)] || [];
                    ['iothread', 'ssd', 'ro'].forEach(o => {
                        if (!crVcPerlFalse(d[o]) && !ok.includes(o)) out.push(crVcErr(k, 'crVcErrDiskBusOpt', { opt: o, bus: crVcBus(k), key: k }));
                    });
                });
                return out;
            } },
            // QS 3589-3600: the IO thread of a SCSI disk works with the VirtIO SCSI single controller only
            { keys: [/^scsi\d+$/, 'scsihw'], run: (e, ch) => {
                if (crVcStr(e.scsihw) === 'virtio-scsi-single') return null;
                const keys = ('scsihw' in ch ? Object.keys(e) : Object.keys(ch)).filter(k => /^scsi\d+$/.test(k) && k in e);
                return keys.filter(k => String(crVcDrive(e[k]).iothread) === '1').map(k => crVcNote(k, 'crVcNoteIothreadScsihw', { key: k }));
            } },
            { keys: ['startup'], run: (e, ch) => ('startup' in ch && crVcStartupBad(ch.startup)) ? crVcErr('startup', 'crVcErrStartup') : null },
        ];

        // --- the parts of the three tabs --------------------------------------------------------------------

        function CrVcAct({ label, icon, onClick, disabled, id }) {
            const I = Icons[icon];
            return (
                <button type="button" className="cr-icon-btn" aria-label={label} title={label} disabled={disabled} data-cr-vc-act={id}
                    onClick={onClick}>{I ? <I className="w-3.5 h-3.5" /> : null}</button>
            );
        }

        // an on/off switch with its help mark beside it
        function CrVcToggle({ id, checked, onChange, label, tip, disabled, mark }) {
            return (
                <div className="cr-vc-toggle">
                    <CrVcSwitch id={id} checked={checked} onChange={onChange} label={label} disabled={disabled} />
                    {tip && <CrVcTip label={label} text={tip} />}
                    {mark}
                </div>
            );
        }

        // one disk: what it is and where it lives, its actions, and the options of its volume
        function CrVcDisk({ h, disk, act }) {
            const { t, raw, val, set, errOf, pend } = h;
            const k = disk.id;
            const v = val(k);
            const cur = crVcStr(v === undefined ? disk.value : v);
            const d = crVcDrive(cur);
            const bus = crVcBus(k);
            const opts = CR_VC_BUS_OPTS[bus] || [];
            const stored = crVcDrive(raw[k] === undefined ? disk.value : raw[k]);
            const setPart = (o, x) => {
                const next = crVcSplice(cur, 'file', o, x);
                if (crVcSameProps(crVcDrive(next), stored)) return h.onRevert(k);
                return set(k, next);
            };
            const on = (o) => String(d[o]) === '1';
            const other = Object.keys(d).filter(o => !CR_VC_DRIVE_OWN.includes(o));
            const advAlert = errOf(k).length > 0 || ['aio', 'replicate', 'ro'].some(o => !crVcSame(d[o], stored[o]));
            const isScsiNoSingle = bus === 'scsi' && crVcStr(h.eff.scsihw) !== 'virtio-scsi-single';
            return (
                <div className="cr-vc-card" data-cr-vc-disk={k}>
                    <div className="cr-vc-card-head">
                        <Icons.HardDrive className="w-4 h-4" />
                        <span className="cr-vc-card-id cr-mono">{k}</span>
                        {disk.storage && <span className="cr-vc-chip" data-cr-vc-storage={disk.storage}>{disk.storage}</span>}
                        <span className="cr-vc-card-meta cr-mono">{disk.size || crVcStr(d.size) || '-'}</span>
                        {(disk.format || d.format) && <span className="cr-vc-card-meta">{disk.format || d.format}</span>}
                        {pend[k] && <span className="cr-vc-chip cr-vc-chip-warn" data-cr-vc-dev-pending={k}>{pend[k].delete ? t('crVcDevRemoveWaits') : t('crVcDevWaits')}</span>}
                        <CrVcMark t={t} row={h.rowOf(k)} onRevert={h.onRevert} />
                        <div className="cr-vc-card-acts">
                            <CrVcAct id="bus" icon="Edit" label={t('editDiskType') || 'Change Bus Type'} onClick={() => act.onEditBus(disk)} />
                            <CrVcAct id="resize" icon="Plus" label={t('resize')} onClick={() => act.onResize(disk)} />
                            <CrVcAct id="move" icon="ArrowRight" label={t('move')} onClick={() => act.onMove(disk)} />
                            {!(disk.volume || '').includes('iso') && !(disk.media || '').includes('cdrom') && (
                                <CrVcAct id="reassign" icon="Users" label={t('reassignOwner') || 'Reassign Owner'} onClick={() => act.onReassign(disk)} />
                            )}
                            <CrVcAct id="detach" icon="Unplug" label={t('detachDisk') || 'Detach'} onClick={() => act.onDetach(k)} />
                            <CrVcAct id="remove" icon="Trash" label={t('remove')} onClick={() => act.onRemove(k)} />
                        </div>
                    </div>
                    <p className="cr-vc-card-vol cr-mono" title={crVcStr(d.file)}>{crVcStr(d.file) || disk.volume}</p>
                    <div className="cr-vc-hw-cols">
                        <div className="cr-vc-col">
                            <CrVcField label={t('crVcDiskCache')} htmlFor={`cr-vc-${k}-cache`} tip={<CrVcTip label={t('crVcDiskCache')} text={t('crVcTipDiskCache')} />}>
                                <select id={`cr-vc-${k}-cache`} data-cr-vc-input={`${k}.cache`} className="cr-select cr-vc-input" value={crVcStr(d.cache)}
                                    onChange={(e) => setPart('cache', e.target.value)}>
                                    <option value="">{t('crVcDefault')}</option>
                                    {CR_VC_CACHE.map(c => <option key={c} value={c}>{c}</option>)}
                                    {d.cache && !CR_VC_CACHE.includes(d.cache) && <option value={d.cache}>{d.cache}</option>}
                                </select>
                            </CrVcField>
                        </div>
                        <div className="cr-vc-col cr-vc-switches">
                            <CrVcToggle id={`${k}.discard`} checked={d.discard === 'on'} label={t('crVcDiskDiscard')} tip={t('crVcTipDiskDiscard')}
                                onChange={(c) => setPart('discard', c ? 'on' : '')} />
                            {opts.includes('ssd') ? (
                                <CrVcToggle id={`${k}.ssd`} checked={on('ssd')} label={t('crVcDiskSsd')} tip={t('crVcTipDiskSsd')}
                                    onChange={(c) => setPart('ssd', c ? 1 : '')} />
                            ) : <p className="cr-vc-hint" data-cr-vc-na={`${k}.ssd`}>{crVcT(t, 'crVcDiskNoOpt', { opt: t('crVcDiskSsd'), bus })}</p>}
                            {opts.includes('iothread') ? (
                                <CrVcToggle id={`${k}.iothread`} checked={on('iothread')} label={t('crVcDiskIothread')}
                                    tip={t(isScsiNoSingle ? 'crVcTipDiskIothreadScsi' : 'crVcTipDiskIothread')}
                                    onChange={(c) => setPart('iothread', c ? 1 : '')} />
                            ) : <p className="cr-vc-hint" data-cr-vc-na={`${k}.iothread`}>{crVcT(t, 'crVcDiskNoOpt', { opt: t('crVcDiskIothread'), bus })}</p>}
                            <CrVcToggle id={`${k}.backup`} checked={String(d.backup) !== '0'} label={t('crVcDiskBackup')} tip={t('crVcTipDiskBackup')}
                                onChange={(c) => setPart('backup', c ? '' : 0)} />
                        </div>
                    </div>
                    <CrVcErrors t={t} list={errOf(k)} />
                    <CrVcFold id={`${k}-adv`} title={t('crVcAdvanced')} alert={advAlert}
                        count={['aio', 'ro'].filter(o => !crVcEmpty(d[o])).length + (String(d.replicate) === '0' ? 1 : 0) + other.length}>
                        <div className="cr-vc-hw-cols">
                            <div className="cr-vc-col">
                                <CrVcField label={t('crVcDiskAio')} htmlFor={`cr-vc-${k}-aio`} tip={<CrVcTip label={t('crVcDiskAio')} text={t('crVcTipDiskAio')} />}>
                                    <select id={`cr-vc-${k}-aio`} data-cr-vc-input={`${k}.aio`} className="cr-select cr-vc-input" value={crVcStr(d.aio)}
                                        onChange={(e) => setPart('aio', e.target.value)}>
                                        <option value="">{t('crVcDefault')}</option>
                                        {CR_VC_AIO.map(c => <option key={c} value={c}>{c}</option>)}
                                    </select>
                                </CrVcField>
                            </div>
                            <div className="cr-vc-col cr-vc-switches">
                                <CrVcToggle id={`${k}.replicate`} checked={String(d.replicate) !== '0'} label={t('crVcDiskReplicate')} tip={t('crVcTipDiskReplicate')}
                                    onChange={(c) => setPart('replicate', c ? '' : 0)} />
                                {opts.includes('ro') && (
                                    <CrVcToggle id={`${k}.ro`} checked={on('ro')} label={t('crVcDiskRo')} tip={t('crVcTipDiskRo')}
                                        onChange={(c) => setPart('ro', c ? 1 : '')} />
                                )}
                            </div>
                        </div>
                        {other.length > 0 && (
                            <div className="cr-vc-kept" data-cr-vc-kept={k}>
                                <span className="cr-vc-hint">{t('crVcKeptParts')}</span>
                                <span className="cr-mono">{other.map(o => `${o}=${d[o]}`).join(', ')}</span>
                            </div>
                        )}
                    </CrVcFold>
                </div>
            );
        }

        // The Disks tab of the preview: the disks with the options of their volumes, the CD/DVD
        // drives, the EFI and TPM volumes and the unused disks, each with the classic actions
        function CrVcDisks({ t, config, changes, crv, onSet, onRevert, act }) {
            const h = crVcTabCtx({ t, config, changes, crv, onSet, onRevert });
            const { pend } = h;
            const all = [...(config.disks || [])].sort(vcDiskOrder);
            const cds = all.filter(crVcDiskIsCd);
            const fw = all.filter(d => !crVcDiskIsCd(d) && crVcDiskIsFw(d));
            const disks = all.filter(d => !crVcDiskIsCd(d) && !crVcDiskIsFw(d));
            const unused = config.unused_disks || [];
            return (
                <div className="cr-vc-hw" data-cr-vc-disks="">
                    <CrVcSection id="disks" title={t('crVcSecDisks')}
                        aside={<div className="cr-vc-sec-acts">
                            <button type="button" className="cr-btn cr-btn-ghost cr-vc-group-act" data-cr-vc-add="iso" onClick={act.onMountIso}><Icons.Disc className="w-3.5 h-3.5" />{t('mountIso')}</button>
                            <button type="button" className="cr-btn cr-btn-ghost cr-vc-group-act" data-cr-vc-add="import" onClick={act.onImportDisk}><Icons.Download className="w-3.5 h-3.5" />{t('importDisk') || 'Import Disk'}</button>
                            <button type="button" className="cr-btn cr-btn-primary cr-vc-group-act" data-cr-vc-add="disk" onClick={act.onAddDisk}><Icons.Plus className="w-3.5 h-3.5" />{t('addDisk')}</button>
                        </div>}>
                        <p className="cr-vc-hint cr-vc-dev-note">{t('crVcDiskOwnRequest')}</p>
                        {disks.length === 0 ? <p className="cr-vc-muted">{t('noDisksConfigured')}</p>
                            : disks.map(d => <CrVcDisk key={d.id} h={h} disk={d} act={act} />)}
                    </CrVcSection>
                    {cds.length > 0 && (
                        <CrVcSection id="media" title={t('crVcSecMedia')}>
                            <ul className="cr-vc-devs">
                                {cds.map(d => {
                                    const empty = String(d.value || '').replace(/\s+/g, '').startsWith('none');
                                    const file = crVcDrive(d.value).file;
                                    return (
                                        <CrVcDevRow key={d.id} t={t} k={d.id} value={empty ? (t('noMedia') || 'No media') : (file || d.volume)} pend={pend[d.id]}
                                            acts={<div className="cr-vc-dev-acts">
                                                <CrVcAct id="iso" icon="Disc" label={empty ? (t('mountIso') || 'Mount ISO') : (t('changeIso') || 'Change ISO')} onClick={() => act.onChangeIso(d.id)} />
                                                {!empty && <CrVcAct id="eject" icon="Unplug" label={t('eject') || 'Eject'} onClick={() => act.onEject(d.id)} />}
                                                <CrVcAct id="detach" icon="Unplug" label={t('detachDisk') || 'Detach'} onClick={() => act.onDetach(d.id)} />
                                                <CrVcAct id="remove" icon="Trash" label={t('remove')} onClick={() => act.onRemove(d.id)} />
                                            </div>} />
                                    );
                                })}
                            </ul>
                            <p className="cr-vc-hint">{t('crVcMediaHint')}</p>
                        </CrVcSection>
                    )}
                    {fw.length > 0 && (
                        <CrVcSection id="fwvol" title={t('crVcSecFwVol')}>
                            <ul className="cr-vc-devs">
                                {fw.map(d => (
                                    <CrVcDevRow key={d.id} t={t} k={d.id} value={d.value} pend={pend[d.id]}
                                        acts={<div className="cr-vc-dev-acts">
                                            <span className="cr-vc-card-meta cr-mono">{d.storage} {d.size}</span>
                                            <CrVcAct id="resize" icon="Plus" label={t('resize')} onClick={() => act.onResize(d)} />
                                            <CrVcAct id="move" icon="ArrowRight" label={t('move')} onClick={() => act.onMove(d)} />
                                        </div>} />
                                ))}
                            </ul>
                            <p className="cr-vc-hint">{t('crVcFwVolHint')}</p>
                        </CrVcSection>
                    )}
                    {unused.length > 0 && (
                        <CrVcSection id="unused" title={`${t('unusedDisks') || 'Unused Disks'} (${unused.length})`}>
                            <p className="cr-vc-hint">{t('unusedDisksDesc') || 'These disks are detached but still exist. You can reattach or delete them.'}</p>
                            <ul className="cr-vc-devs">
                                {unused.map(d => (
                                    <CrVcDevRow key={d.id} t={t} k={d.id} value={d.value} pend={pend[d.id]}
                                        acts={<div className="cr-vc-dev-acts">
                                            <button type="button" className="cr-btn cr-btn-ghost cr-vc-group-act" data-cr-vc-act="reattach" onClick={() => act.onReattach(d)}>{t('reattach') || 'Reattach'}</button>
                                            <button type="button" className="cr-btn cr-btn-ghost cr-vc-group-act cr-vc-danger" data-cr-vc-act="purge" onClick={() => act.onDeleteUnused(d)}>{t('deletePermanently') || 'Delete permanently'}</button>
                                        </div>} />
                                ))}
                            </ul>
                        </CrVcSection>
                    )}
                </div>
            );
        }

        // one network device, edited in place; the draft is the body of the classic edit dialog
        function CrVcNic({ t, net, raw, draft, onField, onRevert, row, issues, pend, bridgeList, hardwareOptions, generateMAC, onToggleLink, onRemove, hot, running }) {
            const b = draft || null;
            const f = (k) => (b ? b[k] : net[k]);
            const id = net.id;
            const errs = issues.filter(e => e.key === id);
            const models = [...(hardwareOptions?.network_models || [{ value: 'virtio', label: 'VirtIO' }])];
            const model = crVcStr(f('model') || 'virtio');
            if (!models.some(m => m.value === model)) models.push({ value: model, label: model });
            const bridge = crVcStr(f('bridge'));
            const local = bridgeList.filter(x => x.source !== 'sdn');
            const sdn = bridgeList.filter(x => x.source === 'sdn');
            const info = bridgeList.find(x => x.iface === bridge);
            const kept = crVcNetKept(raw[id]);
            const down = !!f('link_down');
            const input = (k, extra) => (
                <input id={`cr-vc-${id}-${k}`} data-cr-vc-input={`${id}.${k}`} className={`cr-input cr-vc-input${errs.some(e => !e.note && e.args && e.args.f === k) ? ' cr-vc-invalid' : ''}`}
                    value={crVcStr(f(k))} onChange={(e) => onField(k, e.target.value)} {...(extra || {})} />
            );
            return (
                <div className="cr-vc-card" data-cr-vc-nic={id}>
                    <div className="cr-vc-card-head">
                        <Icons.Network className="w-4 h-4" />
                        <span className="cr-vc-card-id cr-mono">{id}</span>
                        <span className="cr-vc-chip">{model}</span>
                        {down && <span className="cr-vc-chip" data-cr-vc-link="down">{t('networkDisconnected')}</span>}
                        {pend[id] && <span className="cr-vc-chip cr-vc-chip-warn" data-cr-vc-dev-pending={id}>{pend[id].delete ? t('crVcDevRemoveWaits') : t('crVcDevWaits')}</span>}
                        <CrVcMark t={t} row={row} onRevert={onRevert} />
                        <div className="cr-vc-card-acts">
                            <CrVcAct id="link" icon={net.link_down ? 'Plug' : 'Unplug'} disabled={!!draft}
                                label={draft ? t('crVcNicLinkAfter') : (net.link_down ? t('connectNetwork') : t('disconnectNetwork'))}
                                onClick={() => onToggleLink(id, net.link_down)} />
                            <CrVcAct id="remove" icon="Trash" label={t('remove')} onClick={() => onRemove(id)} />
                        </div>
                    </div>
                    <div className="cr-vc-grid">
                        <CrVcField label={t('crVcNicBridge')} htmlFor={`cr-vc-${id}-bridge`} tip={<CrVcTip label={t('crVcNicBridge')} text={t('crVcTipNicBridge')} />}
                            hint={info && info.source === 'sdn' ? crVcT(t, 'crVcNicSdn', { zone: info.zone || 'SDN' }) : null}>
                            <select id={`cr-vc-${id}-bridge`} data-cr-vc-input={`${id}.bridge`} className="cr-select cr-vc-input" value={bridge}
                                onChange={(e) => onField('bridge', e.target.value)}>
                                {bridge && !info && <option value={bridge}>{bridge}</option>}
                                {local.length > 0 && <optgroup label={t('crVcNicLocal')}>{local.map(x => <option key={x.iface} value={x.iface}>{x.iface}{x.comments ? ` - ${x.comments}` : ''}</option>)}</optgroup>}
                                {sdn.length > 0 && <optgroup label={t('crVcNicVnets')}>{sdn.map(x => <option key={x.iface} value={x.iface}>{x.iface} - {x.zone || 'SDN'}{x.alias ? ` (${x.alias})` : ''}</option>)}</optgroup>}
                                {bridgeList.length === 0 && !bridge && <option value="vmbr0">vmbr0</option>}
                            </select>
                        </CrVcField>
                        <CrVcField label={t('crVcNicVlan')} htmlFor={`cr-vc-${id}-tag`} tip={<CrVcTip label={t('crVcNicVlan')} text={t('crVcTipNicVlan')} />}>
                            {input('tag', { type: 'number', min: 1, max: 4094, placeholder: t('crVcNone') })}
                        </CrVcField>
                        <CrVcField label={t('crVcNicModel')} htmlFor={`cr-vc-${id}-model`} tip={<CrVcTip label={t('crVcNicModel')} text={t('crVcTipNicModel')} />}>
                            <select id={`cr-vc-${id}-model`} data-cr-vc-input={`${id}.model`} className="cr-select cr-vc-input" value={model}
                                onChange={(e) => onField('model', e.target.value)}>
                                {models.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                            </select>
                        </CrVcField>
                        <CrVcField label={t('crVcNicMac')} htmlFor={`cr-vc-${id}-macaddr`} tip={<CrVcTip label={t('crVcNicMac')} text={t('crVcTipNicMac')} />}>
                            <div className="cr-vc-inline">
                                {input('macaddr', { placeholder: t('crVcNicMacAuto'), spellCheck: false })}
                                <CrVcAct id="mac" icon="RefreshCw" label={t('crVcNicMacNew')} onClick={() => onField('macaddr', generateMAC())} />
                            </div>
                        </CrVcField>
                        <CrVcField label={t('crVcNicRate')} htmlFor={`cr-vc-${id}-rate`} tip={<CrVcTip label={t('crVcNicRate')} text={t('crVcTipNicRate')} />}>
                            {input('rate', { type: 'number', min: 0, step: 'any', placeholder: t('crVcUnlimited') })}
                        </CrVcField>
                        <CrVcField label={t('crVcNicQueues')} htmlFor={`cr-vc-${id}-queues`} tip={<CrVcTip label={t('crVcNicQueues')} text={t('crVcTipNicQueues')} />}>
                            {input('queues', { type: 'number', min: 0, max: 64, placeholder: '1' })}
                        </CrVcField>
                    </div>
                    <div className="cr-vc-switches cr-vc-switches-row">
                        <CrVcToggle id={`${id}.firewall`} checked={!!f('firewall') && String(f('firewall')) !== '0'} label={t('crVcNicFirewall')} tip={t('crVcTipNicFirewall')}
                            onChange={(c) => onField('firewall', c)} />
                        <CrVcToggle id={`${id}.link`} checked={!down} label={t('crVcNicConnected')} tip={t('crVcTipNicLink')}
                            onChange={(c) => onField('link_down', !c)} />
                    </div>
                    <p className="cr-vc-hint" data-cr-vc-nic-hint={running ? (hot ? 'hot' : 'cold') : 'stopped'}>
                        {t(running ? (hot ? 'crVcNicHintHot' : 'crVcNicHintCold') : 'crVcNicHintStopped')}</p>
                    <CrVcErrors t={t} list={errs} />
                    <CrVcFold id={`${id}-adv`} title={t('crVcAdvanced')} alert={!crVcEmpty(f('mtu')) && !!draft && !crVcSame(f('mtu'), net.mtu)}
                        count={(crVcEmpty(f('mtu')) ? 0 : 1) + kept.length}>
                        <div className="cr-vc-grid">
                            <CrVcField label="MTU" htmlFor={`cr-vc-${id}-mtu`} tip={<CrVcTip label="MTU" text={t('crVcTipNicMtu')} />}>
                                {input('mtu', { type: 'number', min: 1, max: 65520, placeholder: t('crVcNicMtuBridge') })}
                            </CrVcField>
                        </div>
                        {kept.length > 0 && (
                            <p className="cr-vc-hint" data-cr-vc-net-kept={id}>{crVcT(t, 'crVcNicKept', { parts: kept.join(', ') })}</p>
                        )}
                    </CrVcFold>
                </div>
            );
        }

        // The Network tab of the preview: each interface edited in place, saved from the review
        function CrVcNetwork({ t, config, crv, nets, onNets, netInitial, bridgeList, hardwareOptions, generateMAC, onAdd, onToggleLink, onRemove }) {
            const raw = config.raw || {};
            const list = config.networks || [];
            const pend = {};
            if (crv.pend.state === 'ok') crv.pend.rows.forEach(p => { if (p && p.key) pend[p.key] = p; });
            const issues = [...crv.errors, ...(crv.notes || [])];
            const hot = !!crVcHotplug((crv.conf || raw).hotplug).network;
            // a field of one interface: the draft starts from what the classic dialog starts from and
            // goes away when it is back there
            const norm = (x) => (x === true ? '1' : (x === false ? '0' : crVcStr(x)));
            const onField = (net, k, v) => onNets(prev => {
                const init = netInitial(net);
                const next = { ...(prev[net.id] || init), [k]: v };
                const out = { ...prev };
                if (Object.keys(next).every(x => norm(next[x]) === norm(init[x]))) delete out[net.id];
                else out[net.id] = next;
                return out;
            });
            const revert = (id) => onNets(prev => {
                const out = { ...prev };
                delete out[id];
                return out;
            });
            return (
                <div className="cr-vc-hw" data-cr-vc-net="">
                    <CrVcSection id="nics" title={t('networkInterfaces')}
                        aside={<div className="cr-vc-sec-acts">
                            <span className="cr-vc-sec-sum">{crVcT(t, list.length === 1 ? 'crVcNic1' : 'crVcNicN', { n: list.length })}</span>
                            <button type="button" className="cr-btn cr-btn-primary cr-vc-group-act" data-cr-vc-add="net" onClick={onAdd}><Icons.Plus className="w-3.5 h-3.5" />{t('addNetwork')}</button>
                        </div>}>
                        <p className="cr-vc-hint cr-vc-dev-note">{t('crVcNicOwnRequest')}</p>
                        {list.length === 0 ? <p className="cr-vc-muted">{t('noNetworksConfigured')}</p> : list.map(net => (
                            <CrVcNic key={net.id} t={t} net={net} raw={raw} draft={nets[net.id]} onField={(k, v) => onField(net, k, v)}
                                onRevert={revert} row={crv.rows.find(r => r.key === net.id && r.net)} issues={issues} pend={pend}
                                bridgeList={bridgeList || []} hardwareOptions={hardwareOptions} generateMAC={generateMAC}
                                onToggleLink={onToggleLink} onRemove={onRemove} hot={hot} running={crv.running} />
                        ))}
                    </CrVcSection>
                </div>
            );
        }

        // --- the Options tab ----------------------------------------------------------------------------

        // QS 1112-1129: the hotplug features, in the order the classic boxes write them
        const CR_VC_HOT_FEATS = [['disk', 'hotplugDisk'], ['network', 'hotplugNetwork'], ['usb', 'hotplugUsb'], ['memory', 'hotplugMemory'],
                                 ['cpu', 'hotplugCpu'], ['cloudinit', 'crVcHotCloudinit']];

        // the hotplug value with one feature on or off: unset and '1' are network,disk,usb (QS 255-264),
        // '0' is none; written like the classic boxes ('disk,network,usb' plus the new one, '0' for none)
        function crVcHotplugValue(value, feat, onOff) {
            const v = crVcEmpty(value) ? '1' : String(value);
            let parts = v === '1' ? ['disk', 'network', 'usb'] : (v === '0' ? [] : v.split(',').filter(Boolean));
            if (onOff && !parts.includes(feat)) parts.push(feat);
            if (!onOff) parts = parts.filter(p => p !== feat);
            return parts.join(',') || '0';
        }

        // the agent string with one part changed, the others kept (AGENT 16-58: enabled is the default key)
        const crVcAgentValue = (value, part, v) => crVcSplice(crVcStr(value), 'enabled', part, v);
        // AGENT 31-34: freeze-fs at HEAD, freeze-fs-on-backup before (still accepted as its alias)
        const crVcFreezeKey = (p) => ['freeze-fs', 'guest-fsfreeze', 'freeze-fs-on-backup'].find(k => k in p) || 'freeze-fs-on-backup';

        function CrVcOptions({ t, config, changes, crv, onSet, onRevert, bootModel, smbiosCard, onGoto }) {
            const h = crVcTabCtx({ t, config, changes, crv, onSet, onRevert });
            const { raw, val, set, mark, errOf } = h;
            // a 0/1 key; back at its default while it is not stored, it is no change
            const setBool = (k, c, def) => ((crVcEmpty(raw[k]) && (c ? 1 : 0) === def) ? onRevert(k) : set(k, c ? 1 : 0));
            const isOn = (k, def) => (crVcEmpty(val(k)) ? def === 1 : String(val(k)) !== '0');
            // start and shutdown order
            const st = crVcProps(val('startup'), 'order');
            const setStart = (part, v) => {
                const p = { order: st.order, up: st.up, down: st.down };
                p[part] = crVcStr(v).trim();
                const next = crVcPrint(p);
                if (crVcEmpty(next)) return set('startup', null);
                if (crVcSameProps(crVcProps(next, 'order'), crVcProps(raw.startup, 'order'))) return onRevert('startup');
                return set('startup', next);
            };
            // boot order: the classic parse, the classic writes
            const bm = bootModel(config, crVcStr(val('boot')), crVcStr(val('bootdisk')));
            const order = bm.bootDevices;
            const writeBoot = (list) => set('boot', list.length > 0 ? 'order=' + list.join(';') : '');
            const toggleBoot = (dev) => writeBoot(order.includes(dev) ? order.filter(d => d !== dev) : [...order, dev]);
            const moveBoot = (dev, dir) => {
                const i = order.indexOf(dev);
                const j = dir === 'up' ? i - 1 : i + 1;
                if (i < 0 || j < 0 || j >= order.length) return;
                const next = [...order];
                [next[i], next[j]] = [next[j], next[i]];
                writeBoot(next);
            };
            // guest agent
            const agent = crVcProps(val('agent'), 'enabled');
            const agentOn = String(agent.enabled) === '1';
            const setAgent = (part, v) => {
                const next = crVcAgentValue(val('agent'), part, v);
                if (crVcSameProps(crVcProps(next, 'enabled'), crVcProps(raw.agent, 'enabled'))) return onRevert('agent');
                return set('agent', next);
            };
            const fk = crVcFreezeKey(agent);
            // hotplug
            const hp = crVcHotplug(crVcEmpty(val('hotplug')) ? undefined : val('hotplug'));
            const setHot = (feat, c) => {
                const next = crVcHotplugValue(val('hotplug'), feat, c);
                const a = crVcHotplug(next);
                const b = crVcHotplug(crVcEmpty(raw.hotplug) ? undefined : raw.hotplug);
                const same = Object.keys({ ...a, ...b }).every(x => !!a[x] === !!b[x]);
                return same ? onRevert('hotplug') : set('hotplug', next);
            };
            const os = CR_VC_OS.find(o => o[0] === crVcStr(val('ostype')));
            const devIcon = (dev) => {
                const v = crVcStr(raw[dev]);
                if (dev === 'ide2' || v.includes('media=cdrom')) return 'Disc';
                if (/^net\d+$/.test(dev)) return 'Globe';
                return /^(scsi|virtio|ide|sata)\d+$/.test(dev) ? 'HardDrive' : 'Database';
            };
            return (
                <div className="cr-vc-hw" data-cr-vc-opts="">
                    <div className="cr-vc-hw-cols">
                        <div className="cr-vc-col">
                            <CrVcSection id="start" title={t('crVcSecStart')}>
                                <CrVcToggle id="onboot" checked={isOn('onboot', 0)} label={t('startOnBoot')} tip={t('crVcTipOnboot')} mark={mark('onboot')}
                                    onChange={(c) => setBool('onboot', c, 0)} />
                                <div className="cr-vc-field">
                                    <div className="cr-vc-label-row">
                                        <span className="cr-vc-label">{t('crVcLblStartup')}</span>
                                        <CrVcTip label={t('crVcLblStartup')} text={t('crVcTipStartup')} />
                                        {mark('startup')}
                                    </div>
                                    <div className="cr-vc-grid">
                                        {[['order', 'crVcStartOrder', ''], ['up', 'crVcStartUp', 's'], ['down', 'crVcStartDown', 's']].map(([p, l, u]) => (
                                            <CrVcField key={p} label={t(l)} htmlFor={`cr-vc-startup-${p}`}>
                                                <input id={`cr-vc-startup-${p}`} data-cr-vc-input={`startup.${p}`} type="number" min="0" step="1"
                                                    className={`cr-input cr-vc-input${errOf('startup').length ? ' cr-vc-invalid' : ''}`} value={crVcStr(st[p])}
                                                    placeholder={p === 'order' ? t('crVcStartAny') : (u ? t('crVcStartNoDelay') : '')} onChange={(e) => setStart(p, e.target.value)} />
                                            </CrVcField>
                                        ))}
                                    </div>
                                    <CrVcErrors t={t} list={errOf('startup')} />
                                </div>
                                <CrVcToggle id="protection" checked={isOn('protection', 0)} label={t('protection')} tip={t('crVcTipProtection')} mark={mark('protection')}
                                    onChange={(c) => setBool('protection', c, 0)} />
                            </CrVcSection>
                            <CrVcSection id="agent" title={t('qemuGuestAgent')}>
                                <CrVcToggle id="agent" checked={agentOn} label={agentOn ? t('crVcOn') : t('crVcOff')} tip={t('crVcTipAgent')} mark={mark('agent')}
                                    onChange={(c) => setAgent('enabled', c ? 1 : 0)} />
                                {agentOn ? (
                                    <>
                                        <CrVcToggle id="agent.fstrim" checked={String(agent.fstrim_cloned_disks) === '1'} label={t('fstrim')} tip={t('crVcTipFstrim')}
                                            onChange={(c) => setAgent('fstrim_cloned_disks', c ? 1 : '')} />
                                        <CrVcFold id="agent-adv" title={t('crVcAdvanced')} count={(agent.type ? 1 : 0) + (fk in agent ? 1 : 0)}>
                                            <CrVcToggle id="agent.freeze" checked={String(agent[fk]) !== '0'} label={t('crVcAgentFreeze')} tip={t('crVcTipAgentFreeze')}
                                                onChange={(c) => setAgent(fk, c ? '' : 0)} />
                                            <CrVcField label={t('crVcAgentType')} htmlFor="cr-vc-agent-type" tip={<CrVcTip label={t('crVcAgentType')} text={t('crVcTipAgentType')} />}>
                                                <select id="cr-vc-agent-type" data-cr-vc-input="agent.type" className="cr-select cr-vc-input" value={crVcStr(agent.type) || 'virtio'}
                                                    onChange={(e) => setAgent('type', e.target.value === 'virtio' ? '' : e.target.value)}>
                                                    <option value="virtio">virtio</option>
                                                    <option value="isa">isa</option>
                                                </select>
                                            </CrVcField>
                                        </CrVcFold>
                                    </>
                                ) : <p className="cr-vc-hint">{t('qemuGuestAgentHint')}</p>}
                            </CrVcSection>
                            <CrVcSection id="virt" title={t('crVcSecVirt')}>
                                <CrVcToggle id="kvm" checked={isOn('kvm', 1)} label={t('kvmVirtualization')} tip={t('crVcTipKvm')} mark={mark('kvm')}
                                    onChange={(c) => setBool('kvm', c, 1)} />
                                <CrVcToggle id="acpi" checked={isOn('acpi', 1)} label="ACPI" tip={t('crVcTipAcpi')} mark={mark('acpi')}
                                    onChange={(c) => setBool('acpi', c, 1)} />
                                <div className="cr-vc-kvline" data-cr-vc-ostype="">
                                    <span className="cr-vc-kvline-k">{t('osType')}</span>
                                    <span className="cr-vc-kv-v">{os ? t(os[1]) : crVcStr(val('ostype')) || t('crVcNotSet')}
                                        <button type="button" className="cr-vc-link cr-vc-link-gap" onClick={() => onGoto('general')}>{t('crVcOnGeneral')}</button></span>
                                </div>
                            </CrVcSection>
                        </div>
                        <div className="cr-vc-col">
                            <CrVcSection id="boot" title={t('bootOrder') || 'Boot Order'} aside={mark('boot')}>
                                <p className="cr-vc-hint">{t('crVcBootHint')}</p>
                                {bm.sortedDevices.length === 0 ? <p className="cr-vc-muted">{t('noBootDevices') || 'No boot devices found'}</p> : (
                                    <ol className="cr-vc-boot">
                                        {bm.sortedDevices.map(dev => {
                                            const i = order.indexOf(dev);
                                            const I = Icons[devIcon(dev)];
                                            const detail = crVcStr(raw[dev]).split(',')[0];
                                            return (
                                                <li key={dev} className={`cr-vc-boot-row${i >= 0 ? ' cr-vc-boot-on' : ''}`} data-cr-vc-boot={dev} data-cr-vc-boot-pos={i >= 0 ? i + 1 : 0}>
                                                    <input type="checkbox" id={`cr-vc-boot-${dev}`} checked={i >= 0} onChange={() => toggleBoot(dev)} />
                                                    <span className="cr-vc-boot-pos">{i >= 0 ? `${i + 1}.` : '-'}</span>
                                                    {I ? <I className="w-3.5 h-3.5" /> : null}
                                                    <label htmlFor={`cr-vc-boot-${dev}`} className="cr-vc-boot-dev cr-mono">{dev}</label>
                                                    <span className="cr-vc-boot-detail cr-mono" title={crVcStr(raw[dev])}>{detail}</span>
                                                    {i >= 0 && (
                                                        <span className="cr-vc-boot-move">
                                                            <CrVcAct id="up" icon="ChevronUp" label={crVcT(t, 'crVcBootUp', { dev })} disabled={i === 0} onClick={() => moveBoot(dev, 'up')} />
                                                            <CrVcAct id="down" icon="ChevronDown" label={crVcT(t, 'crVcBootDown', { dev })} disabled={i === order.length - 1} onClick={() => moveBoot(dev, 'down')} />
                                                        </span>
                                                    )}
                                                </li>
                                            );
                                        })}
                                    </ol>
                                )}
                            </CrVcSection>
                            <CrVcSection id="hotplug" title={t('hotplug')} aside={mark('hotplug')}>
                                <p className="cr-vc-hint" data-cr-vc-hot-state={crVcEmpty(val('hotplug')) ? 'default' : String(val('hotplug'))}>
                                    {crVcEmpty(val('hotplug')) ? t('crVcHotDefault') : (String(val('hotplug')) === '1' ? t('crVcHotOne') : t('crVcHotHint'))}</p>
                                <div className="cr-vc-switches">
                                    {CR_VC_HOT_FEATS.map(([feat, l]) => (
                                        <CrVcToggle key={feat} id={`hotplug.${feat}`} checked={!!hp[feat]} label={t(l)} tip={t(`crVcTipHot_${feat}`)}
                                            onChange={(c) => setHot(feat, c)} />
                                    ))}
                                </div>
                                <CrVcErrors t={t} list={[...errOf('hotplug'), ...errOf('numa')]} />
                            </CrVcSection>
                        </div>
                    </div>
                    {/* the classic SMBIOS card brings its own title */}
                    <section className="cr-vc-sec" data-cr-vc-sec="smbios">
                        <div className="cr-vc-sec-body cr-vc-slot-body" data-cr-vc-slot="smbios">{smbiosCard}</div>
                    </section>
                </div>
            );
        }

        // the edits of the Disks, Network and Options tabs, read only, for whoever has to hold them
        // against the backend and the Proxmox VE source
        window.PegaProxVmCfgTabs = Object.freeze({
            netBuilt: crVcNetBuilt, netKept: crVcNetKept, checkNets: crVcCheckNets, hotplug: crVcHotplugValue,
            agent: crVcAgentValue, startupBad: crVcStartupBad,
        });
