        // ═══════════════════════════════════════════════════════════
        // React Setup - LW
        // Using production build for performance
        // Babel transpiles on-the-fly (fine for our use case)
        // ═══════════════════════════════════════════════════════════
        const { useState, useEffect, useRef, useCallback, useMemo, createContext, useContext } = React;
        
        // NS: API runs on same origin, Flask serves both frontend and API
        // This makes deployment super easy - just one process
        const API_URL = window.location.origin + '/api';
        // const API_URL = 'http://localhost:5000/api';  // local dev
        // const API_URL = 'https://pegaprox.internal/api' // old staging
        
        // NS: Central version constant - keep in sync with backend PEGAPROX_VERSION
        const PEGAPROX_VERSION = "1.4.1";
        const DEBUG = false; // set true for verbose logging

        // Human-readable cluster label. Rename only writes display_name; name is
        // the value typed at add time and is not unique across clusters.
        const clusterLabel = (c) => (c && (c.display_name || c.name || c.id)) || '';

        // LW Nov 2026 (#1228) - a drag that starts in a dialog (selecting what was typed in a
        // field) and ends on its backdrop makes the browser click the nearest element holding
        // both ends, the backdrop, and the backdrops close their dialogs on click, with all
        // that was typed. That click is dropped before React sees it: it lands on an element
        // around where the press began, and the press was in a field one drags in (text, a
        // slider) or selected text. A click on the backdrop itself, a button pressed on its
        // icon and let go on its label, or a checkbox let go on its label, goes through.
        const DRAG_FIELDS = 'textarea, select, [contenteditable="true"], input:not([type="checkbox"]):not([type="radio"])'
            + ':not([type="button"]):not([type="submit"]):not([type="reset"]):not([type="image"])';
        if (typeof document !== 'undefined' && !window.__ppDragClickGuard) {
            window.__ppDragClickGuard = true;
            let pressedOn = null;
            document.addEventListener('mousedown', (e) => { pressedOn = e.target; }, true);
            document.addEventListener('click', (e) => {
                const from = pressedOn;
                pressedOn = null;
                const to = e.target;
                if (!from || from === to || !(to instanceof Node) || !(from instanceof Node) || !to.contains(from)) return;
                const typing = from instanceof Element && from.closest(DRAG_FIELDS);
                const sel = window.getSelection ? window.getSelection() : null;
                if (typing || (sel && !sel.isCollapsed)) e.stopPropagation();
            }, true);
        }

        // NS: global time formatting — reads user pref from localStorage
        // NS Jul 2026 (perf): fmtDate/fmtTime are called thousands of times per render
        // (every task/log/VM/taskbar timestamp). Each call used dt.toLocaleString(...)
        // which internally CONSTRUCTS a fresh Intl.DateTimeFormat every time — one of
        // the slowest common JS ops. A live Chrome trace (config-modal typing) showed
        // fmtDate alone eating ~1.5s of a few seconds. Cache the formatter per
        // (kind, 12h, options) key and reuse it via .format() — ~100x cheaper, same
        // output. h12 is still read per call so a 12h/24h toggle takes effect at once.
        const _dtfCache = {};
        function _dtf(kind, h12, opts) {
            const key = kind + (h12 ? '1' : '0') + '|' + JSON.stringify(opts || {});
            let f = _dtfCache[key];
            if (!f) {
                const base = kind === 'T'
                    ? { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: h12 }
                    : kind === 'M'
                        ? { hour: '2-digit', minute: '2-digit', hour12: h12 }
                        : { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: h12 };
                try { f = new Intl.DateTimeFormat(undefined, { ...base, ...(opts || {}) }); }
                catch (_) { f = new Intl.DateTimeFormat(); }
                _dtfCache[key] = f;
            }
            return f;
        }
        function fmtDate(d, opts = {}) {
            if (!d) return '';
            const dt = d instanceof Date ? d : new Date(typeof d === 'number' && d < 1e12 ? d * 1000 : d);
            if (isNaN(dt)) return '';
            const h12 = localStorage.getItem('pegaprox-time-format') === '12h';
            return _dtf('D', h12, opts).format(dt);
        }
        function fmtTime(d) {
            if (!d) return '';
            const dt = d instanceof Date ? d : new Date(typeof d === 'number' && d < 1e12 ? d * 1000 : d);
            if (isNaN(dt)) return '';
            const h12 = localStorage.getItem('pegaprox-time-format') === '12h';
            return _dtf('T', h12, null).format(dt);
        }
        // LW Oct 2026 - hour and minute in browser time on the same 12h/24h setting, for
        // chart axes where seconds are noise; opts add parts (month, day, second)
        function fmtClock(d, opts) {
            if (!d) return '';
            const dt = d instanceof Date ? d : new Date(typeof d === 'number' && d < 1e12 ? d * 1000 : d);
            if (isNaN(dt)) return '';
            const h12 = localStorage.getItem('pegaprox-time-format') === '12h';
            return _dtf('M', h12, opts || null).format(dt);
        }

        // NS: timezone list for node time config (matches backend get_timezones)
        const TIMEZONES = [
            'UTC', 'Europe/Berlin', 'Europe/Vienna', 'Europe/Zurich', 'Europe/London',
            'Europe/Paris', 'Europe/Amsterdam', 'Europe/Brussels', 'Europe/Rome',
            'Europe/Madrid', 'Europe/Warsaw', 'Europe/Prague', 'Europe/Budapest',
            'Europe/Stockholm', 'Europe/Helsinki', 'Europe/Athens', 'Europe/Moscow',
            'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
            'America/Toronto', 'America/Vancouver', 'America/Sao_Paulo', 'America/Mexico_City',
            'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Singapore', 'Asia/Seoul',
            'Asia/Dubai', 'Asia/Kolkata', 'Asia/Bangkok', 'Asia/Jakarta',
            'Australia/Sydney', 'Australia/Melbourne', 'Australia/Perth',
            'Pacific/Auckland', 'Pacific/Fiji',
            'Africa/Cairo', 'Africa/Johannesburg', 'Africa/Lagos',
        ];


        // MK Sep 2026 (#642) - a plugin can be limited to certain clusters.
        // Both layouts build their own plugin list, so the rule lives here once.
        // No scope at all means every cluster: that is where every plugin starts and
        // what every installation had before the column existed. Getting this the
        // wrong way round would hide all of them.
        function pluginAppliesToCluster(plugin, clusterId) {
            const scope = (plugin && plugin.clusters) || [];
            if (!scope.length) return true;
            return !!clusterId && scope.indexOf(clusterId) >= 0;
        }

        // LW Oct 2026 (#1159) - the storage figure of a cluster is the room for VM and CT disks.
        // A PBS datastore or a share for backups, ISOs and templates only would blow it up, so
        // only a storage whose content names images or rootdir counts. Same rule as the server.
        function holdsGuestDisks(ds) {
            const c = ds && ds.content;
            const list = Array.isArray(c) ? c : (typeof c === 'string' ? c.split(',') : []);
            return list.some(x => { const v = String(x).trim(); return v === 'images' || v === 'rootdir'; });
        }

        // used/total over a /datastores answer ({shared, local: {node: [...]}}): a shared
        // storage once, a local one per node
        function guestStorageTotals(datastores) {
            const shared = (datastores && datastores.shared) || [];
            const seen = new Set(shared.map(d => d.storage));
            const all = [...shared];
            Object.values((datastores && datastores.local) || {}).forEach(list => {
                (list || []).forEach(d => { if (!seen.has(d.storage)) all.push(d); });
            });
            let used = 0, total = 0;
            all.filter(holdsGuestDisks).forEach(d => { used += d.used || 0; total += d.total || 0; });
            return { used, total };
        }


        // =====================================================
        // TRANSLATION SYSTEM
        // LW: German first because thats what we started with
        // English added later. Some keys might still be missing
        // TODO: Maybe add French/Spanish someday?
        // FIXME: some keys are definitely duplicated, cleanup needed
        // =====================================================
