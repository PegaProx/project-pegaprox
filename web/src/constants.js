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
        const PEGAPROX_VERSION = "Beta 0.9.15";
        const DEBUG = false; // set true for verbose logging

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


        // =====================================================
        // TRANSLATION SYSTEM
        // LW: German first because thats what we started with
        // English added later. Some keys might still be missing
        // TODO: Maybe add French/Spanish someday?
        // FIXME: some keys are definitely duplicated, cleanup needed
        // =====================================================
