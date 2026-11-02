        // ═══════════════════════════════════════════════════════════
        // Corporate Redesigned (Preview): the summary of a VM or container - LW Oct 2026
        // Drawn by CorporateVmDetailView in the preview only, from the reads the view makes
        // anyway (lock, guest agent, config, HA resources, the hour of metrics it loads on
        // open), the guest list row and the backup list the dashboard polls. Only the recovery
        // state (on expand) and the migration check (on a click) ask the server for more.
        // A read that failed, was refused or never ran is said to be, never shown as fine.
        // ═══════════════════════════════════════════════════════════

        // what a read came back with: ok, forbidden, notfound, offline (503), away (#625),
        // limited, error, unreachable (no answer at all). at: the browser's clock
        async function crVmRead(authFetch, url, opts) {
            const r = await authFetch(url, opts);
            const at = Date.now();
            if (!r) return { state: 'unreachable', at };
            if (await haLeaderAway(r)) return { state: 'away', code: r.status, at };
            const body = await r.json().catch(() => null);
            if (r.ok && body && typeof body === 'object' && !body.error) return { state: 'ok', body, code: r.status, at };
            const msg = body && typeof body.error === 'string' ? body.error : '';
            const state = r.status === 403 ? 'forbidden' : r.status === 404 ? 'notfound' : r.status === 503 ? 'offline'
                : r.status === 429 ? 'limited' : 'error';
            return { state, code: r.status, msg, at };
        }

        // the agent switch of a VM config, read the way the server reads it (backup_verify._agent_on)
        function crVmAgentOn(v) {
            const s = String(v == null || v === '' ? '0' : v);
            return s.startsWith('1') || s.includes('enabled=1');
        }

        // file systems that are full by design: snap loops, CD images
        const CR_VM_IMAGE_FS = new Set(['squashfs', 'iso9660', 'udf', 'cramfs', 'erofs', 'cdfs']);
        const crVmHasNum = (v) => typeof v === 'number' && Number.isFinite(v);

        function crVmClock(ms) {
            if (!ms) return '';
            return crFmtClock(ms);
        }
        // a time of today as hh:mm, an older one with its day
        function crVmWhen(ms) {
            if (!ms) return '';
            const d = new Date(ms);
            if (d.toDateString() === new Date().toDateString()) return crVmClock(ms);
            return crFmtClock(ms, { day: '2-digit', month: '2-digit' });
        }
        // a server time as it is stored (naive ISO), short: month-day hour:minute; the title has it whole
        const crVmServerWhen = (s) => (s && typeof s === 'string' ? crDriftTime(s).slice(5) : '');

        // the health of a signal as one of five words, and the tone it is drawn in
        const CR_VM_STATES = {
            healthy: 'success', warning: 'warning', critical: 'error', unknown: 'neutral', unconfigured: 'neutral', na: 'neutral',
        };

        // a read that did not come back ok, in words
        function crVmReadText(read, t) {
            if (!read) return t('crVmNotRead');
            const code = read.code ? ` (HTTP ${read.code})` : '';
            switch (read.state) {
                case 'loading': return t('loading');
                case 'forbidden': return t('crVmNoPermission') + (read.msg ? `: ${read.msg}` : '');
                case 'notfound': return t('crVmNotFound') + code;
                case 'offline': return t('crVmClusterOffline');
                case 'away': return t('crVmLeaderAway');
                case 'limited': return t('crDriftLimited');
                case 'unreachable': return t('crDriftOffline');
                default: return t('crVmReadFailed') + (read.msg ? `: ${read.msg}` : code);
            }
        }

        // PVE HA's state of a resource (the hastate of the guest list), as health
        function crVmHaState(s) {
            const v = String(s || '');
            if (v === 'started' || v === 'stopped') return 'healthy';
            if (v === 'error' || v === 'fence') return 'critical';
            if (['migrate', 'relocate', 'recovery', 'freeze', 'request_stop', 'request_start', 'starting', 'queued', 'ignored'].includes(v)) return 'warning';
            if (v === 'disabled') return 'unconfigured';
            return 'unknown';
        }

        function crVmCan() {
            const { user, isAdmin, haReadOnly } = useAuth();
            return useMemo(() => {
                const list = Array.isArray(user && user.permissions) ? user.permissions : [];
                const holds = (p) => !!isAdmin || list.includes(p);
                // what changes something: never on a read-only standby (#625)
                const can = (p) => (!haReadOnly || haReadPermission(p)) && holds(p);
                return { holds, can };
            }, [user, isAdmin, haReadOnly]);
        }

        // --- the health of the guest ----------------------------------------------

        // one row per signal: what it says, since when, from where, and where it is handled
        function crVmHealthRows(x, t) {
            const { vm, clusterId, isQemu, isRunning, perm } = x;
            const rows = [];
            const row = (id, icon, label, state, badge, detail, more) => rows.push({ id, icon, label, state, badge, detail, ...(more || {}) });

            // backup: the list the dashboard polls for the guest table, when it is of this cluster
            const bf = x.backupFor;
            const backupLink = perm.backup ? { link: { label: t('crVmOpenBackups'), go: () => x.openConfig('backups') } } : {};
            const mine = bf && bf.cluster === clusterId;
            if (!mine || !bf.at) {
                const failed = mine && bf.failed != null;
                row('backup', <Icons.Database />, t('crVmBackup'), 'unknown', failed ? t('crVmReadFailedShort') : t('crVmNotRead'),
                    failed ? crVmReadText({ state: bf.failed === 403 ? 'forbidden' : 'error', code: bf.failed || null }, t) : t('crVmBackupNotYet'), backupLink);
            } else {
                const b = (x.backupStatus || {})[vm.vmid];
                const older = bf.failed != null ? crFill(t('crVmBackupStale'), { time: crVmClock(bf.at), code: bf.failed ? `HTTP ${bf.failed}` : t('crVmNoAnswer') }) : '';
                const when = { when: crVmClock(bf.at), whenTitle: t('crVmReadAt'), ...backupLink };
                if (!b) {
                    row('backup', <Icons.Database />, t('crVmBackup'), 'unknown', t('crVmNoBackupFound'),
                        [t('crVmNoBackupFoundHint'), older].filter(Boolean).join(' '), when);
                } else {
                    const st = b.status === 'ok' ? 'healthy' : b.status === 'warn' ? 'warning' : b.status === 'stale' ? 'critical' : 'unknown';
                    const age = crVmHasNum(b.last_backup_age_hours) ? crVmAge(b.last_backup_age_hours, t) : '-';
                    const bits = [crFill(t('crVmBackupCount'), { n: b.count_30d != null ? b.count_30d : '-' }),
                        b.encrypted ? t('crVmEncrypted') : t('crVmNotEncrypted'),
                        crVmHasNum(b.last_verify_age_hours) ? crFill(t('crVmPbsVerified'), { age: crVmAge(b.last_verify_age_hours, t) }) : t('crVmPbsNotVerified')];
                    row('backup', <Icons.Database />, t('crVmBackup'), st,
                        crFill(t(st === 'unknown' ? 'crVmNoBackupFound' : 'crVmLastBackup'), { age }),
                        [bits.join(' · '), older].filter(Boolean).join(' '),
                        { when: b.last_backup_ts ? crVmWhen(b.last_backup_ts * 1000) : '', whenTitle: `${t('crVmBackupTime')}: ${b.last_backup_ts ? crDate(b.last_backup_ts) : '-'}`,
                          whenFull: true, basis: t('crVmBackupBands'), ...backupLink });
                }
            }

            // backup SLA and restore test: the restore report of this guest, read on expand
            const rr = x.rr;
            if (!perm.backup) {
                ['sla', 'restore'].forEach(id => row(id, id === 'sla' ? <Icons.Clock /> : <Icons.LifeBuoy />, t(id === 'sla' ? 'crVmSla' : 'crVmRestore'),
                    'unknown', t('crVmNoPermissionShort'), crFill(t('crVmNeeds'), { perm: 'backup.view' })));
            } else if (!rr || rr.state !== 'ok') {
                const idle = !rr || rr.state === 'idle';
                ['sla', 'restore'].forEach(id => row(id, id === 'sla' ? <Icons.Clock /> : <Icons.LifeBuoy />, t(id === 'sla' ? 'crVmSla' : 'crVmRestore'),
                    'unknown', idle ? t('crVmNotLoaded') : rr.state === 'loading' ? t('loading') : crVmRecoveryBadge(rr, t),
                    idle ? t('crVmRecoveryOnExpand') : crVmRecoveryText(rr, t), { recovery: true }));
            } else {
                const g = (rr.body && rr.body.guest) || {};
                const sla = g.sla_hours, age = g.newest_backup_age_hours;
                const ageText = crVmHasNum(age) ? crVmAge(age, t) : '-';
                const rpo = {
                    ok: ['healthy', 'crVmSlaOk'], warning: ['warning', 'crVmSlaWarn'], breached: ['critical', 'crVmSlaBreached'],
                    no_backup: [sla ? 'critical' : 'unconfigured', sla ? 'crVmSlaNoBackup' : 'crVmSlaOff'],
                    disabled: ['unconfigured', 'crVmSlaOff'], unknown: ['unknown', 'crVmSlaUnknown'],
                }[g.rpo_state] || ['unknown', 'crVmSlaUnknown'];
                const slaDetail = g.rpo_state === 'unknown' ? t('crVmSlaUnknownHint')
                    : g.rpo_state === 'no_backup' ? [t('crVmNoBackupOnStorages'), sla ? crFill(t('crVmSlaTarget'), { h: sla }) : t('crVmSlaNotSet')].join(' ')
                    : [crFill(t('crVmNewest'), { age: ageText, n: g.backup_count != null ? g.backup_count : '-' }),
                       sla ? crFill(t('crVmSlaTarget'), { h: sla }) : t('crVmSlaNotSet')].join(' · ');
                row('sla', <Icons.Clock />, t('crVmSla'), rpo[0], t(rpo[1]), slaDetail,
                    { recovery: true, when: crVmServerWhen(g.newest_backup_at), whenFull: true,
                      whenTitle: `${t('crVmNewestBackup')}: ${crDriftTime(g.newest_backup_at) || '-'} (${t('crDriftServerTime')})`,
                      basis: t('crVmSlaBands'), link: { label: t('crVmOpenSla'), go: x.open ? () => x.open('sla', clusterId) : null } });

                const state = g.state;
                const restore = { ok: 'healthy', stale: 'warning', rto_missed: 'warning', failing: 'critical', never: 'unknown' }[state] || 'unknown';
                const word = { ok: 'crVmRtPassed', stale: 'crVmRtStale', rto_missed: 'crVmRtRtoMissed', failing: 'crVmRtFailing', never: 'crVmRtNever' }[state] || 'crVmRtUnknown';
                let detail;
                if (state === 'failing') detail = crFill(t('crVmRtCause'), { cause: g.last_failure_cause || '-', time: crDriftTime(g.last_failure_at) });
                else if (state === 'never') detail = t('crVmRtNeverHint');
                else {
                    const checks = Array.isArray(g.last_checks) ? g.last_checks : [];
                    const parts = [crFill(t('crVmRtLastPass'), { time: crDriftTime(g.last_success_at) || '-',
                                                                 days: g.last_success_age_days != null ? g.last_success_age_days : '-' })];
                    if (g.rto_state === 'met' || g.rto_state === 'missed') {
                        parts.push(crFill(t(g.rto_state === 'met' ? 'crVmRtoMet' : 'crVmRtoMissed'), { m: crVmSecs(g.measured_seconds), r: crVmSecs(g.rto_seconds) }));
                    }
                    parts.push(checks.length ? crFill(t('crVmRtChecks'), { ok: checks.filter(c => c && c.ok === true).length,
                        bad: checks.filter(c => c && c.ok === false).length, skip: checks.filter(c => c && c.ok == null).length })
                        : t('crVmRtNoChecks'));
                    detail = parts.join(' · ');
                }
                if (!isQemu) detail = `${detail}. ${t('crVmRtCtProof')}`;
                row('restore', <Icons.LifeBuoy />, t('crVmRestore'), restore, t(word), detail,
                    { recovery: true, when: crVmServerWhen(g.last_test_at), whenFull: true,
                      whenTitle: `${t('crVmLastTest')}: ${crDriftTime(g.last_test_at) || '-'} (${t('crDriftServerTime')})`,
                      basis: t('crVmRtBasis'), link: { label: t('crVmOpenRestoreTests'), go: x.open ? () => x.open('recovery', clusterId) : null } });
            }

            // guest agent: the switch in the options, and whether it answered the read on open
            const cfgRaw = x.config && x.config.state === 'ok' ? (x.config.body.raw || {}) : null;
            const cfgOpt = x.config && x.config.state === 'ok' ? (x.config.body.options || {}) : null;
            const agentCfg = cfgRaw ? (cfgRaw.agent != null ? cfgRaw.agent : cfgOpt && cfgOpt.agent) : null;
            const enabled = cfgRaw ? crVmAgentOn(agentCfg) : null;
            const optLink = perm.config ? { label: t('crVmOpenOptions'), go: () => x.openConfig('options') } : null;
            if (!isQemu) {
                row('agent', <Icons.Terminal />, t('crVmAgent'), 'na', t('crVmNotApplicable'), t('crVmAgentCt'));
            } else {
                const cfgText = enabled == null ? t('crVmAgentCfgUnknown') : enabled ? t('crVmAgentCfgOn') : t('crVmAgentCfgOff');
                const ar = x.agentRead;
                if (!isRunning) {
                    row('agent', <Icons.Terminal />, t('crVmAgent'), enabled === false ? 'unconfigured' : 'unknown',
                        enabled === false ? t('crVmAgentOff') : t('crVmNotWhileStopped'), cfgText, { link: optLink });
                } else if (!ar || ar.state === 'loading') {
                    row('agent', <Icons.Terminal />, t('crVmAgent'), 'unknown', t('loading'), cfgText, { link: optLink });
                } else if (ar.state === 'ok') {
                    const os = x.guestInfo && x.guestInfo.os_pretty_name;
                    row('agent', <Icons.Terminal />, t('crVmAgent'), 'healthy', t('crVmAgentAnswers'), [cfgText, os].filter(Boolean).join(' · '),
                        { when: crVmClock(ar.at), whenTitle: t('crVmReadAt'), link: optLink });
                } else if (ar.state === 'down') {
                    row('agent', <Icons.Terminal />, t('crVmAgent'), enabled === false ? 'unconfigured' : 'warning',
                        enabled === false ? t('crVmAgentOff') : t('crVmAgentSilent'),
                        enabled === false ? t('crVmAgentOffHint') : `${cfgText}. ${t('crVmAgentSilentHint')}`,
                        { when: crVmClock(ar.at), whenTitle: t('crVmReadAt'), link: optLink });
                } else {
                    row('agent', <Icons.Terminal />, t('crVmAgent'), 'unknown', t('crVmReadFailedShort'),
                        [crVmReadText(ar, t), x.guestInfo ? t('crVmAgentOlder') : ''].filter(Boolean).join(' '),
                        { when: crVmClock(ar.at), whenTitle: t('crVmReadAt'), link: optLink });
                }
            }

            // Proxmox HA: the live state from the guest list, the settings from the HA resources
            const sid = `${isQemu ? 'vm' : 'ct'}:${vm.vmid}`;
            const ha = x.haRead;
            const res = ha && ha.state === 'ok' ? (ha.list || []).find(r => r && r.sid === sid) : null;
            const live = vm.hastate ? String(vm.hastate) : '';
            const haLink = x.open ? { label: t('crVmOpenHa'), go: () => x.open('ha', clusterId) } : null;
            const settings = res ? [res.group ? crFill(t('crVmHaGroup'), { g: res.group }) : '',
                crFill(t('crVmHaLimits'), { r: res.max_restart != null ? res.max_restart : '-', l: res.max_relocate != null ? res.max_relocate : '-' }),
                res.state ? crFill(t('crVmHaRequested'), { s: res.state }) : ''].filter(Boolean).join(' · ') : '';
            const haWhen = ha && ha.at ? { when: crVmClock(ha.at), whenTitle: t('crVmReadAt') } : {};
            if (live && ha && ha.state === 'ok' && !res) {
                // the HA resources read after the row: after a removal, or an addition made elsewhere,
                // the two disagree until the guest list catches up. The resource list decides the switch
                row('ha', <Icons.Shield />, t('proxmoxHa'), 'unknown', t('crVmHaDisagree'),
                    crFill(t('crVmHaDisagreeHint'), { s: live, time: crVmClock(ha.at) }), { ...haWhen, link: haLink, ha: true, disagree: true });
            } else if (live) {
                const st = crVmHaState(live);
                row('ha', <Icons.Shield />, t('proxmoxHa'), st, crFill(t('crVmHaLive'), { s: live }),
                    [settings || (ha && ha.state !== 'ok' && ha.state !== 'loading' ? `${t('crVmHaSettingsUnread')}: ${crVmReadText(ha, t)}` : ''),
                     t('crVmHaLiveBasis')].filter(Boolean).join(' · '), { ...haWhen, link: haLink, ha: true, managed: true });
            } else if (!ha || ha.state === 'loading') {
                row('ha', <Icons.Shield />, t('proxmoxHa'), 'unknown', t('loading'), '', { link: haLink, ha: true });
            } else if (ha.state !== 'ok') {
                row('ha', <Icons.Shield />, t('proxmoxHa'), 'unknown', ha.state === 'forbidden' ? t('crVmNoPermissionShort') : t('crVmReadFailedShort'),
                    ha.state === 'forbidden' ? crFill(t('crVmNeeds'), { perm: 'ha.view' }) : crVmReadText(ha, t), { ...haWhen, link: haLink, ha: true });
            } else if (res) {
                row('ha', <Icons.Shield />, t('proxmoxHa'), 'unknown', t('crVmHaConfigured'), `${settings} · ${t('crVmHaNoLive')}`,
                    { ...haWhen, link: haLink, ha: true, managed: true });
            } else {
                row('ha', <Icons.Shield />, t('proxmoxHa'), 'unconfigured', t('crVmHaNotManaged'),
                    (ha.list || []).length ? t('crVmHaNotManagedHint') : t('crVmHaEmptyHint'), { ...haWhen, link: haLink, ha: true });
            }

            // lock: the read on open, and what the guest list says when that read did not work
            const lr = x.lockRead;
            const lockedBy = crVmLockedBy(vm, x.lockInfo, lr);
            if (lockedBy) {
                row('lock', <Icons.Lock />, t('crVmLock'), 'warning', crFill(t('crVmLocked'), { r: lockedBy }),
                    lr && lr.state === 'ok' ? ((x.lockInfo && x.lockInfo.lock_description) || t('crVmLockedHint')) : t('crVmLockFromList'),
                    lr && lr.at ? { when: crVmClock(lr.at), whenTitle: t('crVmReadAt') } : {});
            } else if (!lr || lr.state === 'loading') {
                row('lock', <Icons.Lock />, t('crVmLock'), 'unknown', t('loading'), '');
            } else if (lr.state === 'ok') {
                row('lock', <Icons.Lock />, t('crVmLock'), 'healthy', t('crVmNotLocked'), t('crVmNotLockedHint'), { when: crVmClock(lr.at), whenTitle: t('crVmReadAt') });
            } else {
                row('lock', <Icons.Lock />, t('crVmLock'), 'unknown', t('crVmReadFailedShort'),
                    lr.state === 'undetermined' ? t('crVmLockUndetermined') : crVmReadText(lr, t), { when: crVmClock(lr.at), whenTitle: t('crVmReadAt') });
            }

            // migration readiness: the server's preflight for this guest, on a click
            const pf = x.pf;
            const pfBase = { pf: true, basis: t('crVmPfBasis'), link: x.acts && x.onMigrate ? { label: t('crVmOpenMigrate'), go: x.onMigrate } : null };
            if (!perm.migrate) {
                row('migrate', <Icons.ArrowRight />, t('crVmMigration'), 'unknown', t('crVmNotChecked'), crFill(t('crVmNeeds'), { perm: 'vm.migrate' }), { basis: pfBase.basis });
            } else if (!pf || pf.state === 'idle') {
                row('migrate', <Icons.ArrowRight />, t('crVmMigration'), 'unknown', t('crVmNotChecked'), t('crVmPfOnClick'), pfBase);
            } else if (pf.state === 'loading') {
                row('migrate', <Icons.ArrowRight />, t('crVmMigration'), 'unknown', t('crVmPfChecking'), '', pfBase);
            } else if (pf.state !== 'ok') {
                row('migrate', <Icons.ArrowRight />, t('crVmMigration'), 'unknown', t('crVmPfFailed'), crVmReadText(pf, t), { ...pfBase, when: crVmClock(pf.at), whenTitle: t('crVmReadAt') });
            } else {
                const body = pf.body || {};
                const g = (body.guests || []).find(r => Number(r.vmid) === Number(vm.vmid)) || null;
                const unread = Array.isArray(body.unread) ? body.unread : [];
                const when = body.checked_at ? { when: crVmClock(body.checked_at * 1000), whenTitle: t('crVmCheckedAt') } : {};
                if (body.supported === false || !g) {
                    row('migrate', <Icons.ArrowRight />, t('crVmMigration'), 'unknown', t('crVmPfUnsupported'),
                        g ? (g.reasons || []).map(r => sayReason(t, 'pf_', r)).join(' ') : t('crVmPfNoRow'), { ...pfBase, ...when });
                } else {
                    const reasons = (g.reasons || []).filter(r => r.level !== 'info').map(r => sayReason(t, 'pf_', r));
                    const st = g.verdict === 'blocked' ? 'critical' : g.verdict === 'warning' || unread.length ? 'warning' : 'healthy';
                    const badge = g.verdict === 'blocked' ? t('crVmPfBlocked') : g.verdict === 'warning' ? t('crVmPfWarning')
                        : unread.length ? t('crVmPfReadyPartly') : t('crVmPfReady');
                    const to = g.to ? crFill(t('crVmPfTo'), { node: g.to }) : t('crVmPfNoTarget');
                    const detail = [to, ...reasons, unread.length ? crFill(t('crVmPfUnread'), { what: unread.join(', ') }) : ''].filter(Boolean).join(' · ');
                    row('migrate', <Icons.ArrowRight />, t('crVmMigration'), st, badge, detail, { ...pfBase, ...when, reasons: g.reasons || [] });
                }
            }

            // audit integrity has no per-guest answer; the check of the whole log writes an audit row
            // the config drift of the cluster is navigation only: nothing of it is counted here
            row('audit', <Icons.FileText />, t('crVmAudit'), 'na', t('crVmAuditNotPerGuest'), t('crVmAuditHint'),
                { link: x.onTimeline ? { label: t('crVmOpenTimeline'), go: x.onTimeline } : null,
                  link2: x.open && perm.drift ? { label: t('crVmOpenDrift'), go: () => x.open('drift', clusterId), title: t('crVmOpenDriftTitle') } : null });
            return rows;
        }

        // The guest list keeps a row's object while usage and status stay put, so a stopped guest's
        // hastate and lock would stay as old as the view. They are taken from every frame of the
        // list the dashboard receives (the poll and the stream announce each one)
        function useCrVmLiveRow(vm, clusterId) {
            const [live, setLive] = useState(null);
            useEffect(() => {
                setLive(null);
                const onFrame = (e) => {
                    const d = (e && e.detail) || {};
                    if (d.cluster_id !== clusterId || !Array.isArray(d.rows)) return;
                    const r = d.rows.find(x => x && x.type === vm.type && Number(x.vmid) === Number(vm.vmid));
                    if (!r) return;
                    const next = { hastate: r.hastate ? String(r.hastate) : '', lock: r.lock ? String(r.lock) : '' };
                    setLive(p => (p && p.hastate === next.hastate && p.lock === next.lock ? p : next));
                };
                window.addEventListener('pegaprox-resources-frame', onFrame);
                return () => window.removeEventListener('pegaprox-resources-frame', onFrame);
            }, [vm.vmid, vm.type, clusterId]);
            return live;
        }

        // the lock that holds: the read on open when it worked (fresher than the polled row, and
        // it ends with an Unlock), else the lock the guest list names
        function crVmLockedBy(vm, lockInfo, lockRead) {
            if (lockRead && lockRead.state === 'ok') return lockInfo && lockInfo.locked ? String(lockInfo.lock_reason || '?') : '';
            return vm.lock ? String(vm.lock) : '';
        }

        function crVmAge(hours, t) {
            if (!crVmHasNum(hours)) return '-';
            if (hours < 1) return crFill(t('crVmAgeMin'), { n: Math.max(1, Math.round(hours * 60)) });
            if (hours < 48) return crFill(t('crVmAgeH'), { n: hours.toFixed(1) });
            return crFill(t('crVmAgeD'), { n: (hours / 24).toFixed(1) });
        }

        function crVmSecs(s) {
            if (!crVmHasNum(s)) return '-';
            return s < 120 ? `${Math.round(s)} s` : `${(s / 60).toFixed(1)} min`;
        }

        function crVmRecoveryBadge(rr, t) {
            return { forbidden: t('crVmNoPermissionShort'), notfound: t('crVmRrNotIn'), offline: t('crVmClusterOfflineShort'),
                     away: t('crVmClusterOfflineShort') }[rr.state] || t('crVmReadFailedShort');
        }

        function crVmRecoveryText(rr, t) {
            if (rr.state === 'notfound') return t('crVmRrNotFound');
            if (rr.state === 'offline') return t('crVmClusterOffline');
            if (rr.state === 'error' && rr.code === 400) return rr.msg || t('crVmRrNotPve');
            return crVmReadText(rr, t);
        }

        function CrVmHealth({ vm, clusterId, isQemu, isRunning, acts, authFetch, guestInfo, agentRead, config, lockInfo, lockRead,
                              haRead, onHaChanged, backupStatus, backupFor, onMigrate, onTimeline, openConfig, open }) {
            const { t } = useTranslation();
            const { holds, can } = crVmCan();
            const perm = { backup: holds('backup.view'), migrate: holds('vm.migrate'), config: can('vm.config'), ha: acts && can('ha.config'),
                           drift: holds('admin.audit') || holds('node.maintenance') };
            const [rr, setRr] = useState({ state: 'idle' });
            const [rrOpen, setRrOpen] = useState(false);
            const [pf, setPf] = useState({ state: 'idle' });
            const [haBusy, setHaBusy] = useState(false);
            const [haMsg, setHaMsg] = useState(null);
            // what each line rests on and whose clock its time is: written out on request, not only in a title
            const [basisOpen, setBasisOpen] = useState(false);
            const alive = useRef(true);
            useEffect(() => () => { alive.current = false; }, []);

            const loadRecovery = async () => {
                if (rr.state === 'loading') return;
                setRr({ state: 'loading' });
                const got = await crVmRead(authFetch, `${API_URL}/clusters/${encodeURIComponent(clusterId)}/recovery-report/${vm.vmid}`);
                if (alive.current) setRr(got);
            };
            const toggleRecovery = () => {
                const next = !rrOpen;
                setRrOpen(next);
                // loaded on the first expand, not on open: a cold report lists every backup storage
                if (next && perm.backup && rr.state === 'idle') loadRecovery();
            };
            const checkMigration = async () => {
                if (pf.state === 'loading') return;
                setPf({ state: 'loading' });
                const got = await crVmRead(authFetch, `${API_URL}/clusters/${encodeURIComponent(clusterId)}/migration-preflight`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({ vms: [vm.vmid] }),
                });
                if (alive.current) setPf(got);
            };
            // the classic HA switch with the classic bodies; the server's answer is shown, the state re-read
            const toggleHa = async (on) => {
                if (haBusy) return;
                setHaBusy(true);
                setHaMsg(null);
                const kind = isQemu ? 'vm' : 'ct';
                const base = `${API_URL}/clusters/${clusterId}/proxmox-ha/resources`;
                const got = on
                    ? await crVmRead(authFetch, base, { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                                        body: JSON.stringify({ vmid: vm.vmid, type: kind, max_restart: 3, max_relocate: 3 }) })
                    : await crVmRead(authFetch, `${base}/${kind}:${vm.vmid}`, { method: 'DELETE' });
                if (!alive.current) return;
                setHaBusy(false);
                if (got.state === 'ok') {
                    setHaMsg({ tone: 'success', text: t(on ? 'crVmHaAdded' : 'crVmHaRemoved') });
                    if (onHaChanged) onHaChanged();
                } else {
                    setHaMsg({ tone: 'error', text: `${t('crVmNotDone')}: ${crVmReadText(got, t)}` });
                }
            };

            const rows = crVmHealthRows({ vm, clusterId, isQemu, isRunning, acts, perm, guestInfo, agentRead, config, lockInfo, lockRead,
                                          haRead, backupStatus, backupFor, rr, pf, onMigrate: onMigrate ? () => onMigrate(vm) : null, onTimeline,
                                          openConfig, open }, t);
            const counts = {};
            rows.forEach(r => { counts[r.state] = (counts[r.state] || 0) + 1; });
            const order = ['critical', 'warning', 'healthy', 'unknown', 'unconfigured', 'na'];
            const word = { healthy: t('crVmStHealthy'), warning: t('crVmStWarning'), critical: t('crVmStCritical'), unknown: t('crVmStUnknown'),
                           unconfigured: t('crVmStUnconfigured'), na: t('crVmStNa') };
            const haRow = rows.find(r => r.id === 'ha');
            const g = rr.state === 'ok' && rr.body ? rr.body : null;

            const action = (r) => {
                const out = [];
                if (r.id === 'migrate' && perm.migrate) {
                    out.push(
                        <button key="pf" type="button" className="cr-btn cr-btn-xs" onClick={checkMigration} disabled={pf.state === 'loading'} data-cr-vm-pf="">
                            {pf.state === 'loading' ? <span className="cr-spinner" aria-hidden="true" /> : null}
                            {pf.state === 'idle' ? t('crVmPfCheck') : t('crVmPfAgain')}
                        </button>
                    );
                }
                if (r.id === 'ha' && perm.ha && haRead && (haRead.state === 'ok' || r.managed)) {
                    const managed = !!r.managed;
                    out.push(
                        <button key="ha" type="button" className={`cr-btn cr-btn-xs${managed ? ' cr-btn-danger' : ''}`} disabled={haBusy}
                            onClick={() => toggleHa(!managed)} data-cr-vm-ha-toggle={managed ? 'off' : 'on'}>
                            {haBusy && <span className="cr-spinner" aria-hidden="true" />}
                            {managed ? t('crVmHaRemove') : t('crVmHaAdd')}
                        </button>
                    );
                }
                if (r.link && r.link.go) {
                    out.push(<button key="link" type="button" className="cr-link cr-vm-hlink" onClick={r.link.go} data-cr-vm-hlink={r.id}>{r.link.label}</button>);
                }
                if (r.link2 && r.link2.go) {
                    out.push(<button key="link2" type="button" className="cr-link cr-vm-hlink" onClick={r.link2.go} title={r.link2.title}
                        data-cr-vm-hlink={`${r.id}-2`}>{r.link2.label}</button>);
                }
                return out;
            };

            return (
                <CrPanel title={t('crVmHealth')} className="cr-vm-health" data-cr-vm-health=""
                    actions={(
                        <>
                            <span className="cr-vm-hcounts" data-cr-vm-hcounts="" title={t('crVmCountsHint')}>
                                {order.filter(s => counts[s]).map(s => (
                                    <span key={s} className={`cr-vm-hcount cr-tone-text cr-tone-${CR_VM_STATES[s]}`} data-cr-vm-hcount={s}>{counts[s]} {word[s]}</span>
                                ))}
                            </span>
                            <button type="button" className="cr-link cr-vm-hbasis-btn" aria-expanded={basisOpen} onClick={() => setBasisOpen(v => !v)}
                                data-cr-vm-hbasis-toggle={basisOpen ? 'open' : 'closed'}>{basisOpen ? t('crVmBasisHide') : t('crVmBasisShow')}</button>
                        </>
                    )}>
                    <div className="cr-vm-hrows">
                        {rows.map(r => {
                            const act = action(r);
                            const first = r.recovery && r.id === 'sla';
                            const clock = r.whenTitle && r.when ? (r.whenFull ? r.whenTitle : `${r.whenTitle}: ${r.when}`) : '';
                            const basis = [r.basis, clock].filter(Boolean).join(' ');
                            return (
                                <React.Fragment key={r.id}>
                                    {first && (
                                        <div className="cr-vm-hgroup">
                                            <button type="button" className="cr-vm-hexp" aria-expanded={rrOpen} aria-controls="cr-vm-recovery"
                                                onClick={toggleRecovery} data-cr-vm-recovery={rrOpen ? 'open' : 'closed'}>
                                                <span className="cr-ico" aria-hidden="true">{rrOpen ? <Icons.ChevronDown /> : <Icons.ChevronRight />}</span>
                                                {t('crVmRecovery')}
                                                <span className="cr-muted">{rr.state === 'idle' && perm.backup ? t('crVmRecoveryLoadHint') : ''}</span>
                                            </button>
                                        </div>
                                    )}
                                    <div className={`cr-vm-hrow${r.recovery ? ' cr-vm-hsub' : ''}`} data-cr-vm-h={r.id} data-cr-vm-hstate={r.state}>
                                        <span className="cr-vm-hlabel"><span className="cr-ico" aria-hidden="true">{r.icon}</span>{r.label}</span>
                                        <span className="cr-vm-hbadge" title={word[r.state]}>
                                            <CrBadge tone={CR_VM_STATES[r.state]}>{r.badge}</CrBadge>
                                        </span>
                                        <span className="cr-vm-hdetail" data-cr-vm-hdetail="" title={r.basis || undefined}>{r.detail}</span>
                                        <span className="cr-vm-hwhen" title={r.whenTitle || undefined} data-cr-vm-hwhen="">{r.when || ''}</span>
                                        <span className="cr-vm-hact">{act}</span>
                                    </div>
                                    {basisOpen && basis && <div className="cr-vm-hbasis" data-cr-vm-hbasis={r.id}>{basis}</div>}
                                    {r.id === 'restore' && r.recovery && !rrOpen && <div id="cr-vm-recovery" hidden />}
                                    {r.id === 'restore' && rrOpen && (
                                        <div id="cr-vm-recovery" className="cr-vm-recovery" data-cr-vm-recovery-body={rr.state}>
                                            {!perm.backup ? (
                                                <p className="cr-muted">{crFill(t('crVmNeeds'), { perm: 'backup.view' })}</p>
                                            ) : rr.state === 'loading' ? (
                                                <p className="cr-muted"><span className="cr-spinner" aria-hidden="true" />{t('crVmRrLoading')}</p>
                                            ) : rr.state !== 'ok' ? (
                                                <div className="cr-callout cr-callout-error" role="alert">
                                                    <Icons.AlertCircle className="w-4 h-4" />
                                                    <div>{crVmRecoveryText(rr, t)}</div>
                                                    <button type="button" className="cr-btn cr-btn-xs" onClick={loadRecovery} data-cr-vm-rr-retry="">{t('retry')}</button>
                                                </div>
                                            ) : (
                                                <CrVmRecoveryDetail body={g} isQemu={isQemu} onReload={loadRecovery} at={rr.at}
                                                    onBackups={() => openConfig('backups')} />
                                            )}
                                        </div>
                                    )}
                                    {r.id === 'migrate' && pf.state === 'ok' && (r.reasons || []).length > 0 && (
                                        <ul className="cr-vm-pfreasons" data-cr-vm-pf-reasons="">
                                            {r.reasons.map((x, i) => (
                                                <li key={i} className={`cr-tone-text cr-tone-${x.level === 'blocked' ? 'error' : x.level === 'warning' ? 'warning' : 'neutral'}`}
                                                    data-cr-vm-pf-reason={x.code}>{sayReason(t, 'pf_', x)}</li>
                                            ))}
                                        </ul>
                                    )}
                                    {r.id === 'ha' && haMsg && (
                                        <div className={`cr-vm-hmsg cr-tone-text cr-tone-${haMsg.tone}`} role={haMsg.tone === 'error' ? 'alert' : 'status'} data-cr-vm-ha-msg={haMsg.tone}>{haMsg.text}</div>
                                    )}
                                </React.Fragment>
                            );
                        })}
                    </div>
                    <p className="cr-vm-fine">{t('crVmHealthFoot')}</p>
                </CrPanel>
            );
        }

        // what the restore report says about the last pass, and the last runs
        function CrVmRecoveryDetail({ body, isQemu, onReload, at, onBackups }) {
            const { t } = useTranslation();
            const g = body.guest || {};
            const checks = Array.isArray(g.last_checks) ? g.last_checks : [];
            const history = Array.isArray(body.history) ? body.history : [];
            const plan = body.checks || {};
            const checkName = (c) => ({ agent: t('crVmCkAgent'), booted: t('crVmCkBooted'), port: t('crVmCkPort'), command: t('crVmCkCommand') }[c.check] || c.check);
            const res = (ok) => (ok === true ? ['success', t('crVmCkOk')] : ok === false ? ['error', t('crVmCkFailed')] : ['neutral', t('crVmCkNotRun')]);
            const runTone = (s) => (s === 'passed' ? 'success' : s === 'failed' || s === 'error' ? 'error' : 'neutral');
            return (
                <div className="cr-vm-rr" data-cr-vm-rr="">
                    <div className="cr-vm-rr-head">
                        <span className="cr-muted">{crFill(t('crVmRrRead'), { time: crVmClock(at) })}</span>
                        <span className="cr-vm-rr-acts">
                            {onBackups && <button type="button" className="cr-link" onClick={onBackups} data-cr-vm-open-backups="">{t('crVmOpenBackups')}</button>}
                            <button type="button" className="cr-btn cr-btn-xs" onClick={onReload} data-cr-vm-rr-reload="">
                                <span className="cr-ico" aria-hidden="true"><Icons.RefreshCw /></span>{t('crVmReload')}
                            </button>
                        </span>
                    </div>
                    <div className="cr-vm-rr-cols">
                        <section>
                            <h4 className="cr-vm-h4">{t('crVmRrLastPassChecks')}</h4>
                            {!g.last_success_at ? <p className="cr-muted">{t('crVmRrNoPass')}</p>
                                : checks.length === 0 ? <p className="cr-muted" data-cr-vm-rr-nochecks="">{t('crVmRrZeroChecks')}</p> : (
                                <ul className="cr-vm-checks">
                                    {checks.map((c, i) => {
                                        const [tone, label] = res(c.ok);
                                        return (
                                            <li key={i} data-cr-vm-check={c.check} data-cr-vm-check-ok={c.ok === true ? 'ok' : c.ok === false ? 'failed' : 'skipped'}>
                                                <CrBadge tone={tone}>{label}</CrBadge>
                                                <span className="cr-strong">{checkName(c)}{c.target ? ` ${c.target}` : ''}</span>
                                                {c.detail && <span className="cr-muted">{c.detail}</span>}
                                            </li>
                                        );
                                    })}
                                </ul>
                            )}
                            <p className="cr-vm-fine">{crFill(t('crVmRrPlan'), {
                                agent: plan.agent || '-', ports: (plan.ports || []).join(', ') || '-',
                                cmd: plan.command ? t('crVmRrPlanCmd') : '-', rto: plan.rto_seconds ? crVmSecs(plan.rto_seconds) : '-' })}</p>
                            {!isQemu && <p className="cr-vm-fine" data-cr-vm-ct-proof="">{t('crVmRtCtProofLong')}</p>}
                        </section>
                        <section>
                            <h4 className="cr-vm-h4">{crFill(t('crVmRrHistory'), { n: history.length })}</h4>
                            {history.length === 0 ? <p className="cr-muted">{t('crVmRrNoHistory')}</p> : (
                                <table className="cr-vm-mini" data-cr-vm-rr-history="">
                                    <thead><tr><th>{t('crVmRrStarted')}</th><th>{t('status')}</th><th>{t('crVmRrBackup')}</th><th>{t('crVmRrTook')}</th><th>{t('crVmRrSource')}</th></tr></thead>
                                    <tbody>
                                        {history.map((h, i) => (
                                            <tr key={h.id || i} data-cr-vm-run={h.status || ''}>
                                                <td className="cr-mono">{crDriftTime(h.started_at)}</td>
                                                <td><CrBadge tone={runTone(h.status)}>{h.status || '-'}</CrBadge>{h.cause ? <span className="cr-muted" title={h.cause}> {h.cause}</span> : null}</td>
                                                <td className="cr-mono">{crDriftTime(String(h.backup_time || '')) || '-'}</td>
                                                <td className="cr-mono">{crVmSecs(h.measured_seconds != null ? h.measured_seconds : h.duration_seconds)}</td>
                                                <td>{h.source || '-'}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                            <p className="cr-vm-fine">{t('crVmServerTimes')}</p>
                        </section>
                    </div>
                </div>
            );
        }

        // --- the last hour of metrics ----------------------------------------------

        const CR_VM_SPARKS = [
            { id: 'cpu', key: 'cpu', pct: true }, { id: 'memory', key: 'memory', pct: true },
            { id: 'disk_read', key: 'crVmDiskRead' }, { id: 'disk_write', key: 'crVmDiskWrite' },
            { id: 'net_in', key: 'networkIn' }, { id: 'net_out', key: 'networkOut' },
        ];
        const CR_VM_SPAN = 3600;

        // the samples of one series inside the last 60 minutes of the answer, gaps kept as null
        function crVmWindow(answer, id) {
            const ts = (answer && answer.timestamps) || [];
            const vals = (answer && answer.metrics && answer.metrics[id]) || [];
            const end = ts.length ? ts[ts.length - 1] : null;
            if (end == null) return { pts: [], end: null };
            const pts = [];
            for (let i = 0; i < ts.length; i++) {
                if (ts[i] < end - CR_VM_SPAN) continue;
                const v = vals[i];
                pts.push({ t: ts[i], v: typeof v === 'number' && Number.isFinite(v) ? v : null });
            }
            return { pts, end };
        }

        // the line as path segments: a gap ends one, a lone sample is a dot
        function crVmSparkPath(pts, end, top) {
            const x = (tt) => ((tt - (end - CR_VM_SPAN)) / CR_VM_SPAN * 100).toFixed(2);
            const y = (v) => (23 - (top > 0 ? v / top : 0) * 21).toFixed(2);
            let d = '', segs = 0, open = false;
            pts.forEach(p => {
                if (p.v == null) { open = false; return; }
                if (!open) { d += `M${x(p.t)} ${y(p.v)} `; segs++; open = true; d += 'l0.01 0 '; }
                else d += `L${x(p.t)} ${y(p.v)} `;
            });
            return { d: d.trim(), segs };
        }

        function CrVmSpark({ spec, answer, t }) {
            const { pts, end } = crVmWindow(answer, spec.id);
            const nums = pts.filter(p => p.v != null);
            const label = t(spec.key);
            const fmt = (v) => (spec.pct ? `${v.toFixed(1)}%` : `${crBytes(v)}/s`);
            if (!nums.length) {
                return (
                    <div className="cr-vm-spark cr-vm-spark-none" data-cr-vm-spark={spec.id} data-cr-vm-spark-samples="0">
                        <span className="cr-vm-spark-label">{label}</span>
                        <span className="cr-muted">{t('crVmNoSamples')}</span>
                    </div>
                );
            }
            const last = nums[nums.length - 1];
            const min = Math.min(...nums.map(p => p.v)), max = Math.max(...nums.map(p => p.v));
            const top = spec.pct ? Math.max(max, 1) * 1.1 : max * 1.1;
            const { d, segs } = crVmSparkPath(pts, end, top);
            const gaps = pts.length - nums.length;
            const aria = crFill(t('crVmSparkAria'), { what: label, now: fmt(last.v), min: fmt(min), max: fmt(max) });
            return (
                <div className="cr-vm-spark" data-cr-vm-spark={spec.id} data-cr-vm-spark-samples={nums.length} data-cr-vm-spark-gaps={gaps}>
                    <span className="cr-vm-spark-label">{label}</span>
                    <span className="cr-vm-spark-now" data-cr-vm-spark-now="" title={crFill(t('crVmSparkAsOf'), { time: crVmClock(last.t * 1000) })}>{fmt(last.v)}</span>
                    <svg className="cr-vm-spark-svg" viewBox="0 0 100 24" preserveAspectRatio="none" role="img" aria-label={aria} data-segments={segs}>
                        <path d={d} vectorEffect="non-scaling-stroke" />
                    </svg>
                    <span className="cr-vm-spark-range" data-cr-vm-spark-range="" title={aria}>
                        {crFill(t('crVmMinMax'), { min: fmt(min), max: fmt(max) })}{gaps > 0 ? ` · ${crFill(t('crVmGaps'), { n: gaps })}` : ''}
                    </span>
                </div>
            );
        }

        function CrVmSparks({ isRunning, metrics }) {
            const { t } = useTranslation();
            const { data, loading, failed, range, onRange, onRetry } = metrics;
            // the hour the view loads on open; another range picked on Monitor hides it
            let state = 'ready';
            if (!isRunning) state = 'stopped';
            else if (range !== 'hour') state = 'range';
            else if (failed && !loading) state = 'error';
            else if (!data || loading || (data.timeframe && data.timeframe !== 'hour')) state = 'loading';
            else if (!crAnySamples(data)) state = 'empty';
            const end = data && data.timestamps && data.timestamps.length ? data.timestamps[data.timestamps.length - 1] : null;
            return (
                <CrPanel title={t('crVmLastHour')} className="cr-vm-sparks" data-cr-vm-sparks={state}
                    actions={state === 'ready' && end ? <span className="cr-muted cr-vm-asof" data-cr-vm-asof="">{crFill(t('crVmAsOf'), { time: crVmClock(end * 1000) })}</span> : null}>
                    {state === 'stopped' ? <p className="cr-vm-note">{t('crVmSparkStopped')}</p>
                        : state === 'range' ? (
                            <p className="cr-vm-note">{t('crVmSparkRange')} <button type="button" className="cr-link" onClick={() => onRange('hour')} data-cr-vm-spark-hour="">{t('crVmShowHour')}</button></p>
                        ) : state === 'error' ? (
                            <div className="cr-vm-note cr-tone-text cr-tone-error" role="alert">{t('crPerfFailed')} <button type="button" className="cr-btn cr-btn-xs" onClick={onRetry} data-cr-vm-spark-retry="">{t('retry')}</button></div>
                        ) : state === 'loading' ? <p className="cr-vm-note" role="status"><span className="cr-spinner" aria-hidden="true" />{t('loading')}</p>
                        : state === 'empty' ? <p className="cr-vm-note">{t('crVmSparkEmpty')}</p>
                        : (
                            <div className="cr-vm-spark-grid">
                                {CR_VM_SPARKS.map(s => <CrVmSpark key={s.id} spec={s} answer={data} t={t} />)}
                            </div>
                        )}
                    {state === 'ready' && <p className="cr-vm-fine">{t('crVmSparkFoot')}</p>}
                </CrPanel>
            );
        }

        // --- file systems -----------------------------------------------------------

        // why the file system read of the guest agent came back without a list (vms.py guest-fsinfo)
        function crVmFsWhy(reason, t) {
            const r = String(reason || '');
            if (r === 'agent_not_running') return t('crVmFsWhyAgent');
            const http = r.match(/^proxmox_(\d+)$/);
            if (http) return crFill(t('crVmFsWhyHttp'), { code: http[1] });
            if (r.startsWith('error:')) return r.slice(6).trim() || t('crVmNoAnswer');
            return r || t('crVmNoAnswer');
        }

        function CrVmFilesystems({ vm, clusterId, authFetch, isQemu, isRunning, guestInfo, agentRead }) {
            const { t } = useTranslation();
            const scale = crStoreScale(t);
            const listed = Array.isArray(guestInfo && guestInfo.filesystems) ? guestInfo.filesystems.filter(fs => fs && typeof fs === 'object') : [];
            // guest-info sends an empty list also when its file system call failed or timed out: an
            // empty list is asked once more on its own route, which says why it has none
            const askAgain = !!(isQemu && isRunning && agentRead && agentRead.state === 'ok' && guestInfo && !listed.length && authFetch);
            const [again, setAgain] = useState(null);
            useEffect(() => {
                if (!askAgain) { setAgain(null); return undefined; }
                let live = true;
                setAgain({ state: 'loading' });
                // a tick later: the answer of guest-info lands in two state updates, the list in the second
                const timer = setTimeout(() => {
                    crVmRead(authFetch, `${API_URL}/clusters/${encodeURIComponent(clusterId)}/vms/${vm.node}/qemu/${vm.vmid}/guest-fsinfo`)
                        .then(r => { if (live) setAgain(r); });
                }, 0);
                return () => { live = false; clearTimeout(timer); };
            }, [askAgain, agentRead && agentRead.at]);
            let state, rows = [], at = agentRead && agentRead.at, why = '';
            if (!isQemu) state = 'lxc';
            else if (!isRunning) state = 'stopped';
            else if (!agentRead || agentRead.state === 'loading') state = 'loading';
            else if (agentRead.state === 'down') state = 'down';
            else if (agentRead.state !== 'ok') state = 'failed';
            else if (listed.length) { rows = listed; state = 'ready'; }
            else if (!guestInfo) state = 'loading';
            else if (!again || again.state === 'loading') state = 'checking';
            else if (again.state !== 'ok') { state = 'unread'; why = crVmReadText(again, t); }
            else {
                const b = again.body || {};
                const got = Array.isArray(b.filesystems) ? b.filesystems.filter(fs => fs && typeof fs === 'object') : [];
                if (got.length) { rows = got; state = 'ready'; at = again.at; }
                else if (b.agent_running === true && !b.reason) state = 'none';
                else { state = 'unread'; why = crVmFsWhy(b.reason, t); }
            }
            const fsRow = (fs, i, ro) => {
                const used = crVmHasNum(fs.used_bytes) ? fs.used_bytes : null;
                const total = crVmHasNum(fs.total_bytes) ? fs.total_bytes : null;
                const pct = crVmHasNum(fs.used_pct) ? fs.used_pct : null;
                const tone = ro ? 'neutral' : pct == null ? null : crStoreTone(pct);
                return (
                    <tr key={`${fs.mountpoint}:${i}`} data-cr-vm-fsrow={fs.mountpoint} data-cr-vm-fstone={tone || 'unknown'}>
                        <td className="cr-mono cr-vm-fs-mount" title={fs.name || fs.mountpoint}>{fs.mountpoint}</td>
                        <td>{fs.type ? <span className="cr-vm-fs-type">{fs.type}</span> : '-'}{ro && <span className="cr-muted cr-vm-fs-ro" title={t('crVmFsImageHint')}> {t('crVmFsImage')}</span>}</td>
                        <td className="cr-mono cr-vm-num">{used != null ? crBytes(used) : '-'}</td>
                        <td className="cr-mono cr-vm-num">{used != null && total != null ? crBytes(Math.max(0, total - used)) : '-'}</td>
                        <td className="cr-mono cr-vm-num">{total != null ? crBytes(total) : '-'}</td>
                        <td className="cr-vm-fs-meter">
                            {pct == null ? <span className="cr-muted" title={t('crVmFsPctUnknownHint')} data-cr-vm-fs-unknown="">{t('crVmFsPctUnknown')}</span>
                                : <CrMeter value={pct} digits={1} tone={tone} title={ro ? t('crVmFsImageHint') : scale} />}
                        </td>
                    </tr>
                );
            };
            let body;
            if (state === 'lxc') {
                const total = crVmHasNum(vm.maxdisk) && vm.maxdisk > 0 ? vm.maxdisk : null;
                const used = isRunning && crVmHasNum(vm.disk) ? vm.disk : null;
                const pct = used != null && total ? used / total * 100 : null;
                body = (
                    <>
                        <table className="cr-vm-mini cr-vm-fs" data-cr-vm-fstable="">
                            <thead><tr><th>{t('crVmFsMount')}</th><th>{t('type')}</th><th>{t('crVmUsed')}</th><th>{t('crVmFree')}</th><th>{t('crVmSize')}</th><th>{t('crVmUse')}</th></tr></thead>
                            <tbody>{fsRow({ mountpoint: '/', name: 'rootfs', type: 'rootfs', used_bytes: used, total_bytes: total,
                                            used_pct: pct != null ? Math.round(pct * 10) / 10 : null }, 0, false)}</tbody>
                        </table>
                        <p className="cr-vm-fine">{isRunning ? t('crVmFsCtRoot') : t('crVmFsCtStopped')}</p>
                    </>
                );
            } else if (state === 'ready') {
                body = (
                    <>
                        <table className="cr-vm-mini cr-vm-fs" data-cr-vm-fstable="">
                            <thead><tr><th>{t('crVmFsMount')}</th><th>{t('type')}</th><th>{t('crVmUsed')}</th><th>{t('crVmFree')}</th><th>{t('crVmSize')}</th><th>{t('crVmUse')}</th></tr></thead>
                            <tbody>{rows.map((fs, i) => fsRow(fs, i, CR_VM_IMAGE_FS.has(String(fs.type || '').toLowerCase())))}</tbody>
                        </table>
                        <p className="cr-vm-fine">{crFill(t('crVmFsFoot'), { time: crVmClock(at) })}</p>
                    </>
                );
            } else {
                const text = { stopped: 'crVmFsStopped', loading: 'loading', checking: 'crVmFsChecking', down: 'crVmFsDown', failed: 'crVmFsFailed',
                               none: 'crVmFsNone', unread: 'crVmFsUnread' }[state];
                const spin = state === 'loading' || state === 'checking';
                body = (
                    <p className="cr-vm-note" data-cr-vm-fsnote="" role={state === 'unread' ? 'alert' : undefined}>
                        {spin && <span className="cr-spinner" aria-hidden="true" />}
                        {state === 'unread' ? crFill(t(text), { why }) : t(text)}{state === 'failed' ? ` ${crVmReadText(agentRead, t)}` : ''}
                    </p>
                );
            }
            return (
                <CrPanel title={t('guestFilesystems')} className="cr-vm-fspanel" data-cr-vm-fs={state}
                    actions={state === 'ready' ? <span className="cr-muted" title={scale}>{crFill(t('crVmFsCount'), { n: rows.length })}</span> : null}>
                    {body}
                </CrPanel>
            );
        }

        // --- hardware, by group, each opening its tab of the configuration --------------

        function crVmMib(v) {
            const n = Number(v);
            return Number.isFinite(n) && n > 0 ? crBytes(n * 1024 * 1024) : null;
        }

        function CrVmHardware({ vm, isQemu, config, onOpen, locked }) {
            const { t } = useTranslation();
            const { can } = crVmCan();
            const may = can('vm.config');
            const ok = config && config.state === 'ok';
            const cfg = ok ? config.body : {};
            const raw = cfg.raw || {};
            const hw = cfg.hardware || {};
            const dflt = (v, d) => (v != null && v !== '' ? String(v) : crFill(t('crVmDefault'), { v: d }));
            const disks = Array.isArray(cfg.disks) ? cfg.disks : [];
            const nets = Array.isArray(cfg.networks) ? cfg.networks : [];
            const drives = disks.filter(d => d && d.media !== 'cdrom' && !String(d.value || '').includes('media=cdrom'));
            const cds = disks.filter(d => d && (d.media === 'cdrom' || String(d.value || '').includes('media=cdrom')));
            const unused = Array.isArray(cfg.unused_disks) ? cfg.unused_disks.length : 0;
            const groups = [];
            if (isQemu) {
                const sockets = Number(raw.sockets || hw.sockets || 1), cores = Number(raw.cores || hw.cores || 1);
                groups.push({ id: 'cpu', tab: 'hardware', icon: <Icons.Cpu />, title: t('crVmProcessors'), lines: ok ? [
                    crFill(t('crVmSocketsCores'), { s: sockets, c: cores, n: sockets * cores }),
                    `${t('cpuType')}: ${dflt(raw.cpu, 'kvm64')}`,
                ] : [crFill(t('crVmVcpus'), { n: vm.maxcpu || '-' })] });
                const balloon = raw.balloon;
                groups.push({ id: 'memory', tab: 'hardware', icon: <Icons.MemoryStick />, title: t('memory'), lines: ok ? [
                    crVmMib(raw.memory || hw.memory) || '-',
                    balloon == null || balloon === '' ? '' : Number(balloon) === 0 ? t('crVmBalloonOff') : crFill(t('crVmBalloonMin'), { v: crVmMib(balloon) || balloon }),
                ] : [vm.maxmem ? crBytes(vm.maxmem) : '-'] });
                groups.push({ id: 'disks', tab: 'disks', icon: <Icons.HardDrive />, title: t('disks'), list: ok ? [
                    ...drives.map(d => ({ k: d.id, v: [d.storage, d.size].filter(Boolean).join(' · ') || d.value })),
                    ...cds.map(d => ({ k: d.id, v: `${t('crVmCdrom')}: ${d.volume && d.volume !== 'none' ? d.volume : t('crVmCdEmpty')}` })),
                ] : null, lines: ok ? (unused ? [crFill(t('crVmUnused'), { n: unused })] : []) : [vm.maxdisk ? crFill(t('crVmProvisioned'), { v: crBytes(vm.maxdisk) }) : '-'] });
                groups.push({ id: 'network', tab: 'network', icon: <Icons.Network />, title: t('network'), list: ok ? nets.map(n => ({
                    k: n.id, v: [n.model, n.bridge, n.tag ? `VLAN ${n.tag}` : '', n.firewall ? t('firewall') : '', n.link_down ? t('crVmLinkDown') : ''].filter(Boolean).join(' · '),
                })) : null, lines: [] });
                groups.push({ id: 'firmware', tab: 'hardware', icon: <Icons.Settings />, title: t('crVmFirmware'), lines: ok ? [
                    `${t('biosType')}: ${raw.bios === 'ovmf' ? 'UEFI (OVMF)' : raw.bios ? String(raw.bios) : crFill(t('crVmDefault'), { v: 'SeaBIOS' })}`,
                    `${t('crVmMachine')}: ${dflt(raw.machine, 'i440fx')}`,
                    `${t('crVmScsi')}: ${dflt(raw.scsihw, 'LSI')}`,
                ] : [] });
            } else {
                groups.push({ id: 'cpu', tab: 'resources', icon: <Icons.Cpu />, title: t('crVmProcessors'), lines: ok ? [
                    crFill(t('crVmCores'), { n: raw.cores || hw.cores || vm.maxcpu || '-' }),
                    Number(raw.cpulimit) > 0 ? crFill(t('crVmCpuLimit'), { n: raw.cpulimit }) : t('crVmCpuUnlimited'),
                ] : [crFill(t('crVmVcpus'), { n: vm.maxcpu || '-' })] });
                groups.push({ id: 'memory', tab: 'resources', icon: <Icons.MemoryStick />, title: t('memory'), lines: ok ? [
                    crVmMib(raw.memory || hw.memory) || '-', raw.swap != null ? `${t('swap')}: ${crVmMib(raw.swap) || '0 B'}` : '',
                ] : [vm.maxmem ? crBytes(vm.maxmem) : '-'] });
                groups.push({ id: 'disks', tab: 'disks', icon: <Icons.HardDrive />, title: t('storageTab'), list: ok ? disks.map(d => ({
                    k: d.id, v: [d.storage, d.size, d.mountpoint || (d.id === 'rootfs' ? '/' : '')].filter(Boolean).join(' · ') || d.value,
                })) : null, lines: ok ? [] : [vm.maxdisk ? crFill(t('crVmProvisioned'), { v: crBytes(vm.maxdisk) }) : '-'] });
                groups.push({ id: 'network', tab: 'network', icon: <Icons.Network />, title: t('network'), list: ok ? nets.map(n => ({
                    k: n.id, v: [n.name, n.bridge, n.ip, n.tag ? `VLAN ${n.tag}` : '', n.firewall ? t('firewall') : ''].filter(Boolean).join(' · '),
                })) : null, lines: [] });
            }
            const title = locked ? t('crVmHwLocked') : t('crVmHwOpen');
            return (
                <CrPanel title={isQemu ? t('vmHardware') : t('crVmCtHardware')} className="cr-vm-hw" data-cr-vm-hw={ok ? 'ok' : config && config.state === 'loading' ? 'loading' : 'fallback'}>
                    {!ok && config && config.state !== 'loading' && (
                        <p className="cr-vm-note" data-cr-vm-hw-note="">{crFill(t('crVmCfgUnread'), { why: crVmReadText(config, t) })}</p>
                    )}
                    <div className="cr-vm-hwgroups">
                        {groups.map(gr => {
                            const head = (
                                <>
                                    <span className="cr-ico" aria-hidden="true">{gr.icon}</span>
                                    <span className="cr-vm-hwtitle">{gr.title}</span>
                                    {may && <span className="cr-ico cr-vm-hwgo" aria-hidden="true"><Icons.ChevronRight /></span>}
                                </>
                            );
                            return (
                                <div key={gr.id} className="cr-vm-hwgroup" data-cr-vm-hwgroup={gr.id}>
                                    {may ? (
                                        <button type="button" className="cr-vm-hwhead" onClick={() => onOpen(gr.tab)} data-cr-vm-hwopen={gr.tab}
                                            title={title} aria-label={`${gr.title}: ${title}`}>{head}</button>
                                    ) : <div className="cr-vm-hwhead">{head}</div>}
                                    {gr.lines.filter(Boolean).map((l, i) => <div key={i} className="cr-vm-hwline">{l}</div>)}
                                    {!gr.list && !gr.lines.filter(Boolean).length && <div className="cr-vm-hwline cr-muted">{t('crVmNotRead')}</div>}
                                    {gr.list && (gr.list.length ? (
                                        <dl className="cr-vm-hwlist">
                                            {gr.list.map(it => (
                                                <div key={it.k}><dt className="cr-mono">{it.k}</dt><dd title={it.v}>{it.v || '-'}</dd></div>
                                            ))}
                                        </dl>
                                    ) : <div className="cr-vm-hwline cr-muted">{t('crVmNone')}</div>)}
                                </div>
                            );
                        })}
                    </div>
                    {!may && <p className="cr-vm-fine">{crFill(t('crVmNeeds'), { perm: 'vm.config' })}</p>}
                </CrPanel>
            );
        }

        // --- the rest of the summary -------------------------------------------------

        function CrVmRelated({ vm, clusterId, clusterName, config, nav, haRes }) {
            const { t } = useTranslation();
            const stores = nav && nav.storesOf ? nav.storesOf(clusterId) : null;
            const cfg = config && config.state === 'ok' ? config.body : null;
            const names = cfg ? [...new Set((cfg.disks || []).map(d => d && d.storage).filter(Boolean))] : [];
            const findStore = (name) => {
                if (!stores) return null;
                const shared = (stores.shared || []).find(s => s && s.storage === name);
                if (shared) return { s: shared, node: null };
                const local = ((stores.local || {})[vm.node] || []).find(s => s && s.storage === name);
                return local ? { s: local, node: vm.node } : null;
            };
            const link = (label, fn, hook) => (fn ? <button type="button" className="cr-link" onClick={fn} {...hook}>{label}</button> : label);
            return (
                <CrPanel title={t('relatedObjects')} className="cr-vm-related" data-cr-vm-related="">
                    <dl className="cr-vm-facts">
                        <div><dt>{t('node')}</dt><dd>{link(vm.node, nav && nav.openNode ? () => nav.openNode(clusterId, vm.node) : null, { 'data-cr-vm-go': 'node' })}</dd></div>
                        <div><dt>{t('cluster')}</dt><dd>{link(clusterName || clusterId, nav && nav.openCluster ? () => nav.openCluster(clusterId) : null, { 'data-cr-vm-go': 'cluster' })}</dd></div>
                        {vm.pool && <div><dt>{t('crVmPool')}</dt><dd>{vm.pool}</dd></div>}
                        {haRes && haRes.group && <div><dt>{t('crVmHaGroupLabel')}</dt><dd>{haRes.group}</dd></div>}
                        {names.length > 0 && (
                            <div><dt>{t('storage')}</dt><dd className="cr-vm-stores">
                                {names.map((n, i) => {
                                    const hit = findStore(n);
                                    return (
                                        <React.Fragment key={n}>
                                            {i > 0 && ', '}
                                            {link(n, hit && nav.openStorage ? () => nav.openStorage(clusterId, hit.s, hit.node) : null, { 'data-cr-vm-go': `storage:${n}` })}
                                        </React.Fragment>
                                    );
                                })}
                            </dd></div>
                        )}
                    </dl>
                </CrPanel>
            );
        }

        // the guest agent's own view of the guest, as the classic summary listed it
        function CrVmAgentInfo({ guestInfo, agentRead }) {
            const { t } = useTranslation();
            if (!guestInfo) return null;
            const list = (v) => (Array.isArray(v) ? v : []);
            const nics = list(guestInfo.interfaces).filter(n => n && n.name !== 'lo');
            const users = list(guestInfo.users).filter(u => u && typeof u === 'object');
            const at = agentRead && agentRead.state === 'ok' ? agentRead.at : null;
            const skew = guestInfo.guest_time_ns && at ? (guestInfo.guest_time_ns / 1e6 - at) / 1000 : null;
            return (
                <CrPanel title={t('guestAgentInfo')} className="cr-vm-agentinfo" data-cr-vm-agentinfo={at ? 'fresh' : 'older'}>
                    {!at && <p className="cr-vm-note">{t('crVmAgentOlder')}</p>}
                    <dl className="cr-vm-facts">
                        {guestInfo.hostname && <div><dt>{t('hostname')}</dt><dd>{guestInfo.hostname}</dd></div>}
                        {guestInfo.os_pretty_name && <div><dt>{t('osVersion')}</dt><dd>{guestInfo.os_pretty_name}</dd></div>}
                        {guestInfo.kernel_version && <div><dt>{t('kernel')}</dt><dd title={guestInfo.kernel_version}>{guestInfo.kernel_version}</dd></div>}
                        {nics.map((n, i) => (
                            <div key={n.name || i}><dt className="cr-mono">{n.name}</dt>
                                <dd className="cr-mono" title={list(n.ips).map(ip => ip && ip.address).join(', ')}>
                                    {[n.mac, list(n.ips).filter(Boolean).map(ip => `${ip.address}${ip.prefix ? '/' + ip.prefix : ''}`).join(', ')].filter(Boolean).join(' · ')}
                                </dd></div>
                        ))}
                        {users.length > 0 && <div><dt>{t('loggedInUsers')}</dt><dd>{users.map(u => (u.domain ? `${u.domain}\\${u.user}` : u.user)).join(', ')}</dd></div>}
                        {skew != null && (
                            <div><dt>{t('clockSkew')}</dt>
                                <dd className={`cr-mono cr-tone-text cr-tone-${Math.abs(skew) > 60 ? 'error' : Math.abs(skew) > 5 ? 'warning' : 'success'}`}
                                    title={t('crVmSkewHint')} data-cr-vm-skew="">{skew >= 0 ? '+' : ''}{skew.toFixed(1)} s</dd></div>
                        )}
                    </dl>
                </CrPanel>
            );
        }

        function CrVmConsole({ vm, isQemu, isRunning, consoles, shot, onOpenConsole, onOpenSpice, clusterId }) {
            const { t } = useTranslation();
            return (
                <div className="cr-vm-console" data-cr-vm-console="">
                    <div className={`cr-vm-screen${shot.url ? ' cr-vm-screen-shot' : ''}`}>
                        {shot.url ? (
                            <>
                                <img src={shot.url} alt={t('consolePreview') || 'Console preview'} onClick={() => onOpenConsole(vm)} title={t('launchWebConsole')} />
                                <button type="button" className="cr-icon-btn cr-vm-shot-refresh" onClick={shot.onRefresh} disabled={shot.loading}
                                    title={t('refresh')} aria-label={t('refresh')}>
                                    <span className="cr-ico" aria-hidden="true"><Icons.RefreshCw /></span>
                                </button>
                            </>
                        ) : (
                            <div className="cr-vm-screen-empty">
                                <span className="cr-ico" aria-hidden="true">{isQemu ? <Icons.Monitor /> : <Icons.Box />}</span>
                                <span>{!isRunning ? t('vmStopped') : !consoles ? t('running') : (shot.loading && isQemu ? t('loadingPreview') : t('consoleAvailable'))}</span>
                            </div>
                        )}
                    </div>
                    {consoles && isRunning && (
                        <button type="button" className="cr-btn cr-vm-console-btn" onClick={() => onOpenConsole(vm)}>
                            <span className="cr-ico" aria-hidden="true"><Icons.Terminal /></span>{t('launchWebConsole')}
                        </button>
                    )}
                    {!consoles && isRunning && <HaOnActiveLink vm={vm} clusterId={clusterId} iconClass="w-3.5 h-3.5" className="cr-btn cr-vm-console-btn" />}
                    {consoles && isRunning && isQemu && onOpenSpice && (
                        <button type="button" className="cr-btn cr-btn-ghost cr-vm-console-btn" onClick={() => onOpenSpice(vm)} title={t('spiceConsoleHint')}>
                            <span className="cr-ico" aria-hidden="true"><Icons.ExternalLink /></span>{t('spiceConsole')}
                        </button>
                    )}
                </div>
            );
        }

        // what the guest uses right now, from the guest list the dashboard polls; a stopped guest has no figures
        function CrVmUsage({ vm, isQemu, isRunning }) {
            const { t } = useTranslation();
            const cpu = isRunning && crVmHasNum(vm.cpu) ? vm.cpu * 100 : null;
            const mem = isRunning && vm.maxmem > 0 && crVmHasNum(vm.mem) ? vm.mem / vm.maxmem * 100 : null;
            const diskUsed = isRunning && vm.disk > 0 && vm.maxdisk > 0 ? vm.disk : null;
            const diskPct = diskUsed != null ? diskUsed / vm.maxdisk * 100 : null;
            return (
                <section className="cr-stat-row cr-vm-usage" aria-label={t('crVmUsageNow')} data-cr-vm-usage={isRunning ? 'running' : 'stopped'}>
                    <CrStat id="cpu" label={t('cpuUsage')} value={cpu != null ? crPct(cpu, 1) : '-'} meter={cpu}
                        sub={crFill(t('crVmOfVcpus'), { n: vm.maxcpu || '-' })} />
                    <CrStat id="mem" label={t('ramUsage')} value={mem != null ? crPct(mem, 1) : '-'} meter={mem}
                        sub={mem != null ? crFill(t('crUsedOf'), { used: crBytes(vm.mem), total: crBytes(vm.maxmem) }) : crFill(t('crVmConfigured'), { v: vm.maxmem ? crBytes(vm.maxmem) : '-' })} />
                    <CrStat id="disk" label={t('disk')} value={diskPct != null ? crPct(diskPct, 1) : '-'} meter={diskPct}
                        meterTone={diskPct != null ? crStoreTone(diskPct) : undefined}
                        title={`${isQemu ? t('crVmDiskQemuHint') : t('crVmDiskCtHint')} ${crStoreScale(t)}`}
                        sub={diskUsed != null ? crFill(t('crUsedOf'), { used: crBytes(diskUsed), total: crBytes(vm.maxdisk) })
                            : crFill(t('crVmProvisioned'), { v: vm.maxdisk ? crBytes(vm.maxdisk) : '-' })} />
                    <CrStat id="uptime" label={t('uptime')} value={isRunning && vm.uptime ? crUptime(vm.uptime) : '-'} sub={t('crVmFromList')} />
                </section>
            );
        }

        function crVmFacts(vm, guestInfo) {
            const ips = guestInfo && Array.isArray(guestInfo.ip_addresses) ? guestInfo.ip_addresses.filter(x => typeof x === 'string') : [];
            const tags = Array.isArray(vm.tags) ? vm.tags : String(vm.tags || '').split(/[;,]/).map(s => s.trim()).filter(Boolean);
            return { ips, tags, hostname: guestInfo && guestInfo.hostname };
        }

        // The summary tab of Corporate Redesigned: the classic arrangement (console and usage on top,
        // then hardware next to the related objects) with the health, the last hour and the file
        // systems in between
        function CrVmSummary(p) {
            const { t } = useTranslation();
            const { isQemu, isRunning, clusterId } = p;
            const fresh = useCrVmLiveRow(p.vm, clusterId);
            const vm = useMemo(() => (fresh ? { ...p.vm, hastate: fresh.hastate, lock: fresh.lock } : p.vm), [p.vm, fresh]);
            const facts = crVmFacts(vm, p.guestInfo);
            const description = p.config && p.config.state === 'ok' && p.config.body.raw ? String(p.config.body.raw.description || '').trim() : '';
            const lockedBy = crVmLockedBy(vm, p.lockInfo, p.lockRead);
            const sid = `${isQemu ? 'vm' : 'ct'}:${vm.vmid}`;
            const haRes = p.haRead && p.haRead.state === 'ok' ? (p.haRead.list || []).find(r => r && r.sid === sid) : null;
            const openConfig = (tab) => p.onOpenConfig(vm, tab);
            return (
                <div className="cr-vm" data-cr-vm-summary={isQemu ? 'vm' : 'ct'}>
                    <div className="cr-vm-top">
                        <CrVmConsole vm={vm} isQemu={isQemu} isRunning={isRunning} consoles={p.consoles} shot={p.shot}
                            onOpenConsole={p.onOpenConsole} onOpenSpice={p.onOpenSpice} clusterId={clusterId} />
                        <div className="cr-vm-topmain">
                            <CrVmUsage vm={vm} isQemu={isQemu} isRunning={isRunning} />
                            <dl className="cr-vm-facts cr-vm-facts-row" data-cr-vm-facts="">
                                {facts.hostname && <div><dt>{t('hostname')}</dt><dd>{facts.hostname}</dd></div>}
                                <div><dt>{t('crVmIps')}</dt><dd className="cr-mono" title={facts.ips.join(', ')}>{facts.ips.length ? facts.ips.join(', ') : '-'}</dd></div>
                                {facts.tags.length > 0 && (
                                    <div><dt>{t('tags')}</dt><dd className="cr-vm-tags">{facts.tags.map(tag => <CrBadge key={tag} tone="info" dot={false}>{tag}</CrBadge>)}</dd></div>
                                )}
                                {description && <div className="cr-vm-desc"><dt>{t('description')}</dt><dd>{description}</dd></div>}
                            </dl>
                        </div>
                    </div>
                    {lockedBy && (
                        <div className="cr-callout cr-callout-warning" role="status" data-cr-vm-locked={lockedBy}>
                            <Icons.Lock className="w-4 h-4" />
                            <div>{crFill(t('crVmLockedBanner'), { r: lockedBy })}{p.lockInfo && p.lockInfo.lock_description ? <span className="cr-muted"> ({p.lockInfo.lock_description})</span> : null}</div>
                            {p.acts && p.lockInfo && p.lockInfo.locked && (
                                <button type="button" className="cr-btn cr-btn-xs" onClick={p.onUnlock} data-cr-vm-unlock="">{t('unlock')}</button>
                            )}
                        </div>
                    )}
                    <CrVmHealth vm={vm} clusterId={clusterId} isQemu={isQemu} isRunning={isRunning} acts={p.acts} authFetch={p.authFetch}
                        guestInfo={p.guestInfo} agentRead={p.agentRead} config={p.config} lockInfo={p.lockInfo} lockRead={p.lockRead}
                        haRead={p.haRead} onHaChanged={p.onHaChanged} backupStatus={p.backupStatus} backupFor={p.backupFor}
                        onMigrate={p.acts ? p.onMigrate : null} onTimeline={p.onTimeline} openConfig={openConfig} open={p.open} />
                    <CrVmSparks isRunning={isRunning} metrics={p.metrics} />
                    <CrVmFilesystems vm={vm} clusterId={clusterId} authFetch={p.authFetch} isQemu={isQemu} isRunning={isRunning}
                        guestInfo={p.guestInfo} agentRead={p.agentRead} />
                    <div className="cr-vm-grid2">
                        <CrVmHardware vm={vm} isQemu={isQemu} config={p.config} onOpen={openConfig} locked={!!lockedBy} />
                        <div className="cr-vm-col">
                            <CrVmRelated vm={vm} clusterId={clusterId} clusterName={p.clusterName} config={p.config} nav={p.nav} haRes={haRes} />
                            {isQemu && isRunning && <CrVmAgentInfo guestInfo={p.guestInfo} agentRead={p.agentRead} />}
                        </div>
                    </div>
                </div>
            );
        }
