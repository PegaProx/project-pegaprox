        // ═══════════════════════════════════════════════
        // PegaProx - Contexts
        // LanguageContext + AuthContext providers
        // ═══════════════════════════════════════════════
        // Language Context
        // LW: Default is German (de) since thats what we use internally
        const LanguageContext = createContext();

        // NS May 2026 (#389): supported language allowlist — reused for input validation
        // both at init (localStorage) and at switch time. Keep in sync with the
        // backend allowlist in pegaprox/api/users.py and the LanguageSwitcher list.
        const SUPPORTED_LANGS = ['de', 'en', 'it', 'fr', 'es', 'pt', 'ko', 'zh', 'pl'];

        // map navigator.language ("en-US", "de-AT", ...) onto a supported code, or null
        function _detectBrowserLang() {
            try {
                const langs = [];
                if (navigator.languages && navigator.languages.length) langs.push(...navigator.languages);
                if (navigator.language) langs.push(navigator.language);
                for (const raw of langs) {
                    if (typeof raw !== 'string' || !raw) continue;
                    const parts = raw.toLowerCase().split(/[-_]/);
                    const base = parts[0];
                    // This project currently ships Simplified Chinese only. Skip
                    // explicitly Traditional Chinese preferences so zh-TW/zh-Hant
                    // can fall through to the user's next preferred language.
                    if (base === 'zh' && (
                        parts.includes('hant') ||
                        parts.includes('tw') ||
                        parts.includes('hk') ||
                        parts.includes('mo')
                    )) continue;
                    if (SUPPORTED_LANGS.includes(base)) return base;
                }
            } catch (_) { /* navigator unavailable / locked down */ }
            return null;
        }

        // LW Oct 2026 (#1189, #1167) - the layout and language an admin pinned for everyone in
        // Settings > Server. A public read, so the login page knows the language as well.
        // Whatever goes wrong here counts as no lock, the server holds the line anyway.
        const NO_UI_LOCK = { layout: '', language: '', admins: false };
        const UI_LOCK_LAYOUTS = ['modern', 'corporate', 'cloud'];

        function cleanUiLock(d) {
            if (!d || typeof d !== 'object') return null;
            return {
                layout: UI_LOCK_LAYOUTS.includes(d.layout) ? d.layout : '',
                language: SUPPORTED_LANGS.includes(d.language) ? d.language : '',
                admins: d.admins === true,
            };
        }

        // null when the read fails
        async function fetchUiLock() {
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), 5000);
            try {
                const r = await fetch(`${API_URL}/interface/lock`, {
                    credentials: 'include', cache: 'no-store', signal: ctrl.signal
                });
                return r.ok ? cleanUiLock(await r.json()) : null;
            } catch (_) {
                return null;
            } finally {
                clearTimeout(timer);
            }
        }

        // The last answer is kept in this browser. A console window (#767) is opened from
        // the app, which has just read it, so it goes by that copy and asks the server for
        // nothing but its console. Only a hint for the page: the server checks every save.
        function cachedUiLock() {
            try { return cleanUiLock(JSON.parse(localStorage.getItem('pegaprox-ui-lock') || 'null')) || NO_UI_LOCK; }
            catch (_) { return NO_UI_LOCK; }
        }
        const UI_LOCK_FROM_CACHE = (() => {
            try { return !!new URLSearchParams(window.location.search).get('console'); }
            catch (_) { return false; }
        })();

        // nobody signed in (role null) is held too; admins only once the lock says so
        function uiLockBinds(lock, role) {
            return !!lock && (lock.admins || role !== 'admin');
        }

        function LanguageProvider({ children }) {
            // Persist language preference in localStorage.
            // NS May 2026 (#389): validate stored value against allowlist
            // (defence in depth — protects against tampered localStorage), and
            // when no valid value is stored, fall back to browser language.
            const [language, setLanguage] = useState(() => {
                try {
                    const saved = localStorage.getItem('pegaprox-language');
                    if (saved && SUPPORTED_LANGS.includes(saved)) return saved;
                } catch (_) {}
                const detected = _detectBrowserLang();
                if (detected) return detected;
                return 'de';
            });

            // `language` above stays the user's own choice. A lock only covers it, so lifting
            // the lock brings that choice back. lockRole is the signed-in account's role as
            // AuthProvider reports it, null while nobody is signed in.
            const [uiLock, setUiLock] = useState(cachedUiLock);
            const [lockRole, setLockRole] = useState(null);
            const uiLockLoad = useRef(null);
            // what the page goes by right now, for the answers below
            const uiLockNow = useRef(uiLock);
            // a lock from the server (the public read, or a UI_LOCKED refusal that brings it)
            const takeUiLock = useCallback((got) => {
                const l = cleanUiLock(got);
                if (!l) return uiLockNow.current;
                try { localStorage.setItem('pegaprox-ui-lock', JSON.stringify(l)); } catch (_) {}
                const prev = uiLockNow.current;
                if (prev.layout !== l.layout || prev.language !== l.language || prev.admins !== l.admins) {
                    uiLockNow.current = l;
                    setUiLock(l);
                }
                return uiLockNow.current;
            }, []);
            // one fetch shared by everyone asking; fresh = ask the server again. Only the
            // newest answer is kept, an older one landing late must not undo it. A read that
            // fails keeps what the page has: the last answer, or no lock when there is none.
            const loadUiLock = useCallback((fresh) => {
                if (fresh || !uiLockLoad.current) {
                    const read = (UI_LOCK_FROM_CACHE && !fresh) ? Promise.resolve(cachedUiLock()) : fetchUiLock();
                    const p = read.then(got => (got && uiLockLoad.current === p) ? takeUiLock(got) : uiLockNow.current);
                    uiLockLoad.current = p;
                }
                return uiLockLoad.current;
            }, [takeUiLock]);
            // the refusal of a save carries the lock, so there is no second read to fail
            const takeRefusedLock = useCallback((body) => {
                if (body && body.lock) {
                    uiLockLoad.current = Promise.resolve(takeUiLock(body.lock));
                } else {
                    loadUiLock(true);
                }
            }, [takeUiLock, loadUiLock]);
            useEffect(() => { loadUiLock(); }, [loadUiLock]);

            const lockedLanguage = (uiLock.language && uiLockBinds(uiLock, lockRole)) ? uiLock.language : '';
            const shown = lockedLanguage || language;

            // Translation function with English fallback
            const t = useCallback((key) => {
                return translations[shown]?.[key] || translations['en']?.[key] || key;
            }, [shown]);

            // Internal: validate + persist locally. Used by both code paths.
            const _setAndPersist = useCallback((lang) => {
                if (!SUPPORTED_LANGS.includes(lang)) return false;
                setLanguage(lang);
                try { localStorage.setItem('pegaprox-language', lang); } catch (_) {}
                return true;
            }, []);

            // changeLanguage = user-initiated switch from an authenticated context.
            // Persists locally AND syncs to the server so other devices pick it up.
            // NS May 2026 (#389) — caller is responsible for only invoking this when
            // authenticated; the switcher uses applyLanguage on the login page.
            const changeLanguage = useCallback((lang) => {
                // nothing to switch while the admin pinned it, and nothing to send:
                // the server would refuse it with UI_LOCKED anyway
                if (lockedLanguage) return;
                if (!_setAndPersist(lang)) return;
                fetch(`${API_URL}/user/preferences`, {
                    method: 'PUT', credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ language: lang })
                }).then(async r => {
                    // pinned after this page loaded: catch up so the switcher goes away
                    if (r && r.status === 403) {
                        const body = await r.json().catch(() => null);
                        if (body && body.code === 'UI_LOCKED') takeRefusedLock(body);
                    }
                }).catch(() => {}); // fire and forget
            }, [_setAndPersist, lockedLanguage, takeRefusedLock]);

            // applyLanguage just sets state+localStorage without API call.
            // Used on login/session restore AND on the unauth login page.
            // Under a lock this only records the user's own choice, what shows stays the lock.
            const applyLanguage = useCallback((lang) => {
                _setAndPersist(lang);
            }, [_setAndPersist]);

            return(
                <LanguageContext.Provider value={{ language: shown, t, changeLanguage, applyLanguage, supportedLangs: SUPPORTED_LANGS,
                                                   languageLocked: !!lockedLanguage, uiLock, loadUiLock, takeRefusedLock, setLockRole }}>
                    {children}
                </LanguageContext.Provider>
            );
        }

        function useTranslation() {
            return useContext(LanguageContext);
        }

        // the switcher's list, also what Settings > Server offers to pin
        function languageChoices(t) {
            return [
                { code: 'de', flag: '🇦🇹', label: 'DE', title: 'Deutsch' },  // NS: AT flag is intentional (German is spoken in Austria too) — do NOT swap it for the German flag
                { code: 'en', flag: '🇬🇧', label: 'EN', title: 'English' },
                { code: 'it', flag: '🇮🇹', label: 'IT', title: 'Italiano' },
                { code: 'fr', flag: '🇫🇷', label: 'FR', title: 'Français' },
                { code: 'es', flag: '🇪🇸', label: 'ES', title: 'Español (LATAM)' },
                { code: 'pt', flag: '🇧🇷', label: 'PT', title: 'Português' },
                { code: 'ko', flag: '🇰🇷', label: 'KO', title: '한국어' },
                { code: 'zh', flag: '🇨🇳', label: 'ZH', title: t('languageSimplifiedChinese') },
                { code: 'pl', flag: '🇵🇱', label: 'PL', title: 'Polski' },
            ];
        }

        // Language Switcher Component
        function LanguageSwitcher() {
            const { language, t, changeLanguage, applyLanguage, languageLocked } = useTranslation();
            const { isCorporate } = useLayout();
            // NS May 2026 (#389): On the login page (unauthenticated) we must NOT
            // hit /api/user/preferences - it would always 401 and spam the console.
            // useAuth() reads cleanly here because LanguageSwitcher is rendered
            // inside both providers in the tree.
            const auth = useContext(AuthContext);
            const switchLang = (auth && auth.isAuthenticated) ? changeLanguage : applyLanguage;
            // pinned by the admin, there is nothing to pick
            if (languageLocked) return null;
            const langs = languageChoices(t);
            const activeLanguage = langs.find(l => l.code === language) || langs[0];

            if (isCorporate) {
                return(
                    <div
                        className="flex items-center gap-2 border border-proxmox-border px-2 py-1.5"
                        style={{ background: 'var(--corp-surface-1)' }}
                    >
                        <span className="text-base leading-none" aria-hidden="true">{activeLanguage.flag}</span>
                        <select
                            value={language}
                            onChange={(e) => switchLang(e.target.value)}
                            className="bg-transparent text-xs text-gray-200 border-0 p-0 pr-6 focus:ring-0 focus:outline-none"
                            aria-label="Select language"
                            title={activeLanguage.title}
                        >
                            {langs.map(l => (
                                <option key={l.code} value={l.code}>
                                    {l.label} - {l.title}
                                </option>
                            ))}
                        </select>
                    </div>
                );
            }

            return(
                <div className="flex items-center gap-1 bg-proxmox-dark rounded-lg p-1 border border-proxmox-border">
                    {langs.map(l => (
                        <button
                            key={l.code}
                            onClick={() => !l.soon && switchLang(l.code)}
                            className={`flex items-center gap-1 px-1.5 py-1 rounded text-sm transition-all ${language === l.code ? 'bg-proxmox-orange text-white' : l.soon ? 'text-gray-600 cursor-not-allowed' : 'text-gray-400 hover:text-white'}`}
                            title={l.title}
                            disabled={l.soon}
                        >
                            <span className={`text-base ${l.soon ? 'opacity-50' : ''}`}>{l.flag}</span>
                            <span className="hidden sm:inline text-xs">{l.label}</span>
                        </button>
                    ))}
                </div>
            );
        }

        // ============================================
        // Authentication System
        // NS: Simple session-based auth. Sessions stored server-side.
        // Passwords hashed with bcrypt on backend.
        // ============================================
        
        const AuthContext = createContext();

        // the layout a lock pins for this account, '' when it keeps its own
        function lockedLayoutFor(lock, u) {
            return (u && lock && lock.layout && uiLockBinds(lock, u.role)) ? lock.layout : '';
        }

        // the palettes that belong to a layout rather than to the theme grid
        const LAYOUT_PALETTES = ['corporateDark', 'corporateLight', 'cloud'];

        // The theme to paint once a lock decides the layout instead of
        // the user. u carries ui_layout as the server sends it (their own choice).
        // Corporate goes by the top bar toggle as it does for its own users (#743: a
        // 'system' choice stays), Cloud wears its palette, and Modern drops the palette of
        // the user's own Corporate or Cloud layout for the server default.
        function lockedTheme(theme, u, lockedLayout, defaultTheme) {
            if (lockedLayout === 'cloud') return 'cloud';
            if (lockedLayout === 'corporate' && theme !== 'system') {
                let light = false;
                try { light = localStorage.getItem('corp-theme') === 'light'; } catch (_) {}
                return light ? 'corporateLight' : 'corporateDark';
            }
            if (lockedLayout === 'modern' && (u?.ui_layout || 'modern') !== 'modern' && LAYOUT_PALETTES.includes(theme)) {
                return (PEGAPROX_THEMES[defaultTheme] && !LAYOUT_PALETTES.includes(defaultTheme)) ? defaultTheme : 'proxmoxDark';
            }
            return theme;
        }

        function AuthProvider({ children }) {
            const { t, applyLanguage, uiLock, loadUiLock, takeRefusedLock, setLockRole } = useTranslation();
            const [user, setUser] = useState(null);
            // NS: Security fix - session cookie is HttpOnly (can't be stolen by XSS)
            // But we also keep sessionId in memory for WebSocket auth (not in localStorage!)
            const [sessionId, setSessionId] = useState(null);
            const [isAuthenticated, setIsAuthenticated] = useState(false);
            const [loading, setLoading] = useState(true);
            const [error, setError] = useState(null);
            const [passwordExpiry, setPasswordExpiry] = useState(null);  // LW: Track password expiration
            const [requires2FASetup, setRequires2FASetup] = useState(false);  // NS: Feb 2026 - Force 2FA setup
            const [ldapEnabled, setLdapEnabled] = useState(false);  // MK: Feb 2026 - LDAP available
            const [oidcEnabled, setOidcEnabled] = useState(false);  // NS: Feb 2026 - OIDC available
            const [oidcButtonText, setOidcButtonText] = useState('Sign in with SSO');
            const [loginBackground, setLoginBackground] = useState('');
            const [reverseProxyEnabled, setReverseProxyEnabled] = useState(false);
            // MK May 2026 — when /auth/check returns initialized=false the install
            // hasn't run the first-admin setup yet. Frontend gates this to render
            // <SetupWizard /> instead of <LoginScreen />.
            const [needsSetup, setNeedsSetup] = useState(false);
            // LW Sep 2026 (#625) - role of this instance in a warm standby pair, as the
            // server reports it on login and /auth/check. A standby also sends peer_url
            // and last_sync_at for the banner, and forwarding: true while it hands
            // changes to the active. serving: true on a member that serves users as an
            // active instance, leader_reachable: false once the leader stops answering.
            const [ha, setHa] = useState({ role: 'standalone' });
            // LW Oct 2026 (#1189) - the layout an admin pinned for this account, '' when it
            // picks its own. The server default theme is kept for lockedTheme().
            const layoutLock = lockedLayoutFor(uiLock, user);
            const defaultThemeRef = useRef('');
            
            // Check session on mount
            useEffect(() => {
                checkSession();
            }, []);

            // the lock changed while signed in (an admin saved it for admins too, or a refused
            // save read it again). The first run is the session start, which painted already.
            // Corporate and Cloud repaint in useLayout; Modern takes the user's own theme
            // back, or the default when that belongs to their own other layout.
            const paintedLock = useRef(null);
            useEffect(() => {
                if (!user) { paintedLock.current = null; return; }
                if (paintedLock.current === null || paintedLock.current === layoutLock) {
                    paintedLock.current = layoutLock;
                    return;
                }
                paintedLock.current = layoutLock;
                if ((layoutLock || user.ui_layout || 'modern') !== 'modern') return;
                const own = user.theme || defaultThemeRef.current || 'proxmoxDark';
                applyTheme(lockedTheme(own, user, layoutLock, defaultThemeRef.current));
            }, [user, layoutLock]);

            // keeps the old object when nothing changed, so a poll does not re-render
            // every useAuth() consumer for nothing
            const applyHa = (next) => {
                const v = (next && typeof next === 'object' && next.role) ? next : { role: 'standalone' };
                setHa(prev => JSON.stringify(prev) === JSON.stringify(v) ? prev : v);
            };

            // re-read only the ha part of /auth/check (last sync time, role after a sync)
            const refreshHa = useCallback(async () => {
                try {
                    const r = await fetch(`${API_URL}/auth/check?t=${Date.now()}`, { credentials: 'include' });
                    if (!r.ok) return;
                    const d = await r.json();
                    if (d.authenticated) applyHa(d.ha);
                } catch (_) {}
            }, []);

            // a standby syncs every few seconds; without this the banner would show the
            // sync time from the moment of login forever.
            // LW Oct 2026 (#625) - the leader too: a page opened there while the group was manual
            // has to hear once it fails over automatically, and then within seconds when the
            // leader is gone or a new one takes over
            useEffect(() => {
                if (!isAuthenticated || (ha.role !== 'standby' && ha.role !== 'active')) return;
                const h = setInterval(refreshHa, ha.automatic === true ? 10000 : 30000);
                return () => clearInterval(h);
            }, [isAuthenticated, ha.role, ha.automatic, refreshHa]);

            // a change refused because the group has no leader right now, or hands the lead on
            // (503 HA_NO_LEASE / HA_TRANSFER, see authFetch): the banner says so at once
            useEffect(() => {
                if (!isAuthenticated) return;
                let last = 0;
                const onLease = () => {
                    if (Date.now() - last < 2000) return;
                    last = Date.now();
                    refreshHa();
                };
                window.addEventListener('pegaprox-ha-lease', onLease);
                return () => window.removeEventListener('pegaprox-ha-lease', onLease);
            }, [isAuthenticated, refreshHa]);
            
            // check if session still valid (cookie is sent automatically)
            const checkSession = async () => {
                // NS Aug 2026 (#681) — while an OIDC callback is being exchanged the session
                // does not exist yet (the callback POST is what creates it), so the 401 here is
                // expected. Do NOT run the check-and-logout on the callback: logout() races the
                // in-flight callback request and aborts it — the Firefox nginx-499 /
                // "Network error during OIDC callback". LoginScreen owns the callback (it looks
                // for the same code+state) and reloads on success, at which point this runs
                // cleanly against the freshly-created session.
                try {
                    const _sp = new URLSearchParams(window.location.search);
                    if (_sp.get('code') && _sp.get('state')) {
                        setLoading(false);
                        return;
                    }
                } catch (_) {}
                // the lock is read alongside the session and loading waits
                // for both, so a pinned user never sees their own layout for a moment first
                const lockLoad = loadUiLock();
                try {
                    // Add cache-busting to prevent stale data
                    const r = await fetch(`${API_URL}/auth/check?t=${Date.now()}`, {
                        credentials: 'include',
                        headers: { 
                            'Cache-Control': 'no-cache, no-store, must-revalidate',
                            'Pragma': 'no-cache'
                        }
                    });
                    
                    if (r && r.ok) {
                        const d = await r.json();
                        // NS: removed session response log (leaked session_id to console)
                        // LW May 2026 — persist air-gap flag for the next page
                        // load so the boot script knows to skip CDN/font fetches.
                        try {
                            if (d.air_gap_mode) localStorage.setItem('pegaprox-air-gap', '1');
                            else localStorage.removeItem('pegaprox-air-gap');
                        } catch (_) {}
                        if (d.authenticated) {
                            // NS: portal_only users must not access main dashboard
                            // LW Oct 2026 (#810) - send them to the portal instead of signing them out,
                            // the session stays. Loading stays on so the login form never flashes.
                            if (d.user?.portal_only && !window.location.pathname.startsWith('/portal')) {
                                window.location.replace('/portal');
                                return;
                            }
                            const lock = await lockLoad;
                            // before setUser: an exempt admin's dashboard opens in their own language
                            setLockRole(d.user?.role || '');
                            defaultThemeRef.current = d.default_theme || '';
                            setUser(d.user);
                            setIsAuthenticated(true);
                            // NS: Get session_id from response for WebSocket auth
                            if (d.session_id) {
                                setSessionId(d.session_id);
                            }
                            // LW: Store password expiry info if present
                            if (d.password_expiry) {
                                setPasswordExpiry(d.password_expiry);
                            }
                            // NS: Check if server requires 2FA setup
                            if (d.requires_2fa_setup) {
                                setRequires2FASetup(true);
                            } else {
                                setRequires2FASetup(false);
                            }
                            // NS: Mar 2026 - apply user's saved language (server overrides local)
                            if (d.user?.language && translations[d.user.language]) {
                                applyLanguage(d.user.language);
                            }
                            // NS: Apply user's theme or default
                            // MK May 2026 — when user is in corporate layout, the local corp-theme
                            // toggle in the top bar is the source of truth. Corporate doesn't use the
                            // theme grid (it's hidden there), so the toggle and server user.theme stay
                            // in sync; reading the toggle avoids a stale server value overriding it on F5.
                            let userTheme = d.user?.theme || d.default_theme || 'proxmoxDark';
                            try {
                                // LW Sep 2026 (#743) - 'system' is a deliberate choice and outranks
                                // the local toggle; reading corp-theme here would turn "follow my
                                // desktop" into whatever the toggle was last set to.
                                if (d.user?.ui_layout === 'corporate' && userTheme !== 'system') {
                                    const isLight = localStorage.getItem('corp-theme') === 'light';
                                    userTheme = isLight ? 'corporateLight' : 'corporateDark';
                                }
                            } catch (_) {}
                            userTheme = lockedTheme(userTheme, d.user, lockedLayoutFor(lock, d.user), d.default_theme);
                            console.log('[Theme] checkSession - Server theme:', d.user?.theme, 'Default:', d.default_theme, 'Using:', userTheme);
                            if (userTheme && PEGAPROX_THEMES[userTheme]) {
                                applyTheme(userTheme);
                            }
                            // NS: Store reverse proxy status
                            if (d.reverse_proxy_enabled !== undefined) {
                                setReverseProxyEnabled(d.reverse_proxy_enabled);
                            }
                            applyHa(d.ha);
                        } else {
                            logout();
                        }
                    } else {
                        // NS: Feb 2026 - Capture ldap_enabled from 401 response
                        try {
                            const errData = await r.json();
                            if (errData.ha_role) applyHa({ role: errData.ha_role });
                            if (errData.ldap_enabled !== undefined) setLdapEnabled(errData.ldap_enabled);
                            if (errData.oidc_enabled !== undefined) { setOidcEnabled(errData.oidc_enabled); setOidcButtonText(errData.oidc_button_text || 'Sign in with SSO'); }
                            if (errData.login_background) setLoginBackground(errData.login_background);
                            if (errData.reverse_proxy_enabled !== undefined) setReverseProxyEnabled(errData.reverse_proxy_enabled);
                            // MK May 2026 — first-run signal from backend
                            if (errData.initialized === false) setNeedsSetup(true);
                            else setNeedsSetup(false);
                        } catch(e) {}
                        logout();
                    }
                } catch (err) {
                    console.error('Session check failed');
                    logout();
                }
                await lockLoad;  // never rejects, see fetchUiLock
                setLoading(false);
            };
            
            // -lw: Main login handler - supports 2FA flow + remember me
            const login = async (username, password, totpCode = '', remember = false, webauthnProof = '') => {
                setError(null);
                // a login page can stay open for days, the session starts on the lock as it is now
                const lockLoad = loadUiLock(true);
                try {
                    const resp = await fetch(`${API_URL}/auth/login`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password, totp_code: totpCode, remember, webauthn_proof: webauthnProof })
                    });
                    
                    const data = await resp.json();
                    
                    // Rate-limit / lockout — server returns 401+locked for user lockouts
                    // (audit #5: uniform 401 stops username enumeration) and 429 for IP-level.
                    // Both carry data.locked + data.retry_after.
                    if (data.locked) {
                        // user-friendly error message derived from retry_after, since
                        // the server response stays generic ("Invalid credentials") to avoid
                        // leaking which users exist
                        const sec = data.retry_after || 0;
                        const mins = Math.ceil(sec / 60);
                        setError(t('accountLocked')
                            ? t('accountLocked').replace('{mins}', mins)
                            : `Too many failed attempts. Try again in ~${mins} min.`);
                        return { success: false, locked: true, retry_after: sec };
                    }
                    if (resp.status === 429) {
                        setError(data.error || 'Too many requests, slow down.');
                        return { success: false, locked: false };
                    }
                    
                    // 2fa required?
                    if (resp.ok && data.requires_2fa) {
                        // -lw #746: pass the server's `methods` through — the login screen branches
                        // on it to show the security-key prompt. Without it twoFAMethods stayed []
                        // and a WebAuthn-only account only ever saw the TOTP box (i.e. locked out).
                        return { requires_2fa: true, methods: data.methods };
                    }
                    
                    if (resp.ok && data.success) {
                        // portal_only users can't use main dashboard
                        if (data.portal_only && !window.location.pathname.startsWith('/portal')) {
                            setError(t('portalOnlyAccount') || 'This account can only log in via the Client Portal (/portal)');
                            // #810 - the message stays up while the portal loads with this session
                            window.location.replace('/portal');
                            return { success: false, portal_only: true };
                        }
                        const lock = await lockLoad;
                        setLockRole(data.user?.role || '');
                        defaultThemeRef.current = data.default_theme || '';
                        setUser(data.user);
                        setIsAuthenticated(true);
                        // NS: Keep session_id in memory for WebSocket auth
                        if (data.session_id) {
                            setSessionId(data.session_id);
                        }
                        // NS: Feb 2026 - Check if force 2FA setup is required
                        if (data.requires_2fa_setup) {
                            setRequires2FASetup(true);
                        }
                        // NS: Mar 2026 - apply user's saved language on login
                        if (data.user?.language && translations[data.user.language]) {
                            applyLanguage(data.user.language);
                        }
                        // NS: Apply user's theme (with fallback to default)
                        let userTheme = data.user?.theme || data.default_theme || 'proxmoxDark';
                        try {
                            if (data.user?.ui_layout === 'corporate' && userTheme !== 'system') {
                                const isLight = localStorage.getItem('corp-theme') === 'light';
                                userTheme = isLight ? 'corporateLight' : 'corporateDark';
                            }
                        } catch (_) {}
                        userTheme = lockedTheme(userTheme, data.user, lockedLayoutFor(lock, data.user), data.default_theme);
                        console.log('[Theme] Login - Server theme:', data.user?.theme, 'Default:', data.default_theme, 'Using:', userTheme);
                        if (userTheme && PEGAPROX_THEMES[userTheme]) {
                            applyTheme(userTheme);
                        }
                        // NS: Store reverse proxy status
                        if (data.reverse_proxy_enabled !== undefined) {
                            setReverseProxyEnabled(data.reverse_proxy_enabled);
                        }
                        applyHa(data.ha);
                        // NS: Security warning for default password
                        if (data.security_warning === 'DEFAULT_PASSWORD') {
                            setTimeout(() => {
                                alert('⚠️ SECURITY WARNING!\n\nYou are using the default admin password.\nPlease change it immediately in Settings ↑ Users!');
                            }, 500);
                        }
                        return { success: true };
                    } else {
                        setError(data.error || 'Login failed');
                        return { success: false, error: data.error };
                    }
                } catch (err) {
                    console.error('login err', err);
                    setError('Connection error');
                    return { success: false, error: 'Connection error' };
                }
            };
            
            // LW: Update user preferences (theme, language, ui_layout)
            const updatePreferences = async (prefs) => {
                try {
                    if (DEBUG) console.log('updatePreferences:', Object.keys(prefs));
                    const r = await fetch(`${API_URL}/user/preferences`, {
                        method: 'PUT',
                        credentials: 'include',
                        headers: { 
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(prefs)
                    });
                    if (DEBUG) console.log('updatePreferences status:', r.status);
                    
                    if (r.ok) {
                        const data = await r.json();
                        if (DEBUG) console.log('updatePreferences: ok');
                        
                        // Update user in state
                        setUser(currentUser => {
                            const updated = {
                                ...currentUser,
                                theme: data.theme,
                                language: data.language,
                                ui_layout: data.ui_layout,
                                taskbar_auto_expand: data.taskbar_auto_expand,
                                sidebar_show_vmid: data.sidebar_show_vmid,
                                layout_chosen: data.layout_chosen
                            };
                            // LW: state updated, no log needed
                            return updated;
                        });
                        
                        // Apply theme immediately AND save to localStorage
                        // under a pinned layout the stored theme can belong to the
                        // user's own one; only a theme picked just now is painted as it is
                        if (data.theme && PEGAPROX_THEMES[data.theme]) {
                            const theme = (layoutLock && !('theme' in prefs))
                                ? lockedTheme(data.theme, data, layoutLock, defaultThemeRef.current)
                                : data.theme;
                            applyTheme(theme);
                        }
                        return { success: true, data };
                    }
                    
                    const errorData = await r.json().catch(() => ({}));
                    console.error('updatePreferences: Request failed:', errorData);
                    // pinned after this page loaded (or the lock read failed): follow the lock
                    // the refusal brings
                    if (r.status === 403 && errorData.code === 'UI_LOCKED') takeRefusedLock(errorData);
                    return { success: false, error: errorData.error, code: errorData.code };
                } catch (e) {
                    console.error('Failed to update preferences:', e);
                    return { success: false, error: e.message };
                }
            };

            const updateCurrentUser = (updates) => {
                setUser(currentUser => currentUser ? { ...currentUser, ...updates } : currentUser);
            };
            
            const logout = async () => {
                try {
                    await fetch(`${API_URL}/auth/logout`, {
                        method: 'POST',
                        credentials: 'include'
                    });
                } catch (err) {
                    console.error('Logout request failed:', err);
                }
                setLockRole(null);
                setUser(null);
                setSessionId(null);
                setIsAuthenticated(false);
                // LW: #295 — re-fetch login page info so OIDC button shows after logout
                try {
                    const r = await fetch(`${API_URL}/auth/check?t=${Date.now()}`, { credentials: 'include' });
                    const d = await r.json();
                    if (d.oidc_enabled !== undefined) { setOidcEnabled(d.oidc_enabled); setOidcButtonText(d.oidc_button_text || 'Sign in with SSO'); }
                    if (d.ldap_enabled !== undefined) setLdapEnabled(d.ldap_enabled);
                    if (d.login_background) setLoginBackground(d.login_background);
                    applyHa(d.ha_role ? { role: d.ha_role } : null);
                } catch(e) {}
            };
            
            // NS: No more X-Session-ID header needed for fetch - cookies are automatic
            // But sessionId is still available for WebSocket URLs
            // #782 (Frisch12) — stable identity. getAuthHeaders returns a constant {} (auth is via
            // credentials:'include'), but a fresh function every render propagates through authFetch
            // -> every component's fetchHealth/poll useCallback -> its effect, re-arming the 60s
            // timers on every SSE-driven render (the ~4 req/s idle storm). useCallback([]) pins it.
            const getAuthHeaders = useCallback(() => {
                return {};  // Empty - credentials: 'include' handles auth for fetch
            }, []);
            
            // LW Sep 2026 (#625 v2) - a standby may be connected to the clusters, but only the
            // active acts on them. One flag for every place that hides actions; isAdmin stays
            // as it is, the HA tab and the promote flow hang off it.
            // A standby that forwards hands every change to the active, so it shows the
            // actions again. It is read-only while it does not (switched off here, or the
            // active it follows does not answer). haStandby holds on every standby: the
            // settings that belong to this instance or are saved on the leader only.
            // haConsolesElsewhere: consoles, shells, SPICE and the console preview run on the
            // leader, except on a member that serves users, which opens them itself.
            // haServing: that member, an active instance to its users, so its texts name
            // the leader where a standby's say "the active instance".
            const haStandby = ha.role === 'standby';
            const haReadOnly = haStandby && ha.forwarding !== true;
            const haConsolesElsewhere = haStandby && ha.serving !== true;
            const haServing = haStandby && ha.serving === true;

            return(
                <AuthContext.Provider value={{ user, sessionId, isAuthenticated, loading, error, login, logout, getAuthHeaders, isAdmin: user?.role === 'admin', passwordExpiry, requires2FASetup, setRequires2FASetup, updatePreferences, updateCurrentUser, ldapEnabled, oidcEnabled, oidcButtonText, loginBackground, reverseProxyEnabled, needsSetup, setNeedsSetup, ha, refreshHa, haReadOnly, haStandby, haConsolesElsewhere, haServing, layoutLock }}>
                    {children}
                </AuthContext.Provider>
            );
        }

        // #625 v2 - what a standby still lets through the permission helpers: the *.view ones
        function haReadPermission(permission) {
            return typeof permission === 'string' && permission.endsWith('.view');
        }

        // #625 - a list only the leader keeps (drift, firing alerts, the push inbox) answers
        // 503 HA_ACTIVE_UNREACHABLE on a member while the leader does not answer, rather
        // than this instance's own rows. The view that asked says so instead of showing an
        // empty list; authFetch leaves such a read without a toast.
        async function haLeaderAway(res) {
            if (!res || res.status !== 503) return false;
            const body = await res.clone().json().catch(() => null);
            return !!body && body.code === 'HA_ACTIVE_UNREACHABLE';
        }

        // LW Oct 2026 (#625) - the maintenance and update of the nodes as the leader runs them,
        // over the node figures this instance reads itself. progress is the leader's
        // /node-progress answer for clusterId ({cluster, nodes}); a node it names takes
        // all five fields from it, the others keep their own. Same object when nothing
        // changes, so nothing renders again for it.
        const HA_NODE_JOB_FIELDS = ['maintenance_mode', 'maintenance_task', 'maintenance_acknowledged', 'is_updating', 'update_task'];
        function haWithLeaderProgress(metrics, progress, clusterId) {
            const nodes = progress && progress.cluster === clusterId ? progress.nodes : null;
            if (!metrics || !nodes || typeof nodes !== 'object') return metrics;
            let out = metrics;
            Object.keys(nodes).forEach(name => {
                const here = metrics[name], there = nodes[name];
                if (!here || typeof here !== 'object' || !there || typeof there !== 'object') return;
                if (out === metrics) out = { ...metrics };
                const job = {};
                HA_NODE_JOB_FIELDS.forEach(k => { job[k] = there[k] ?? (k.endsWith('_task') ? null : false); });
                out[name] = { ...here, ...job };
            });
            return out;
        }

        // #625 - this view on the active instance, for what a standby never runs itself.
        // peer_url is the active as this standby reaches it (a path behind a proxy stays);
        // search is '' for its start page or a console window's '?console=...'. Only an
        // https:// address gives a link, anything else null, and then no link is shown.
        function haActiveHref(peerUrl, search = '') {
            if (typeof peerUrl !== 'string' || !/^https:\/\/\S+$/i.test(peerUrl.trim())) return null;
            try {
                const u = new URL(peerUrl.trim().replace(/\/*$/, '/'));
                if (u.protocol !== 'https:') return null;
                u.search = search || '';
                u.hash = '';
                return u.href;
            } catch (_) {
                return null;
            }
        }

        // the key a console window (#767) takes: cluster, type, vmid, node. Cluster ids are
        // synced, so the active knows the same one. '' for anything that has no window.
        function haConsoleSearch(vm, clusterId) {
            const cid = (vm && vm._clusterId) || clusterId;
            if (!vm || !cid || (vm.type !== 'qemu' && vm.type !== 'lxc')) return '';
            return '?console=' + encodeURIComponent(`${cid}:${vm.type}:${vm.vmid}:${vm.node}`);
        }

        // the same from a click handler; false when there is no address to go to
        function haOpenOnActive(peerUrl, search = '') {
            const href = haActiveHref(peerUrl, search);
            if (href) window.open(href, '_blank', 'noopener,noreferrer');
            return !!href;
        }
        
        function useAuth() {
            return useContext(AuthContext);
        }

        // LW: Feb 2026 - layout hook (reads from user preferences)
        // returns layout type and convenience boolean for corporate mode
        function useLayout() {
            const { user, layoutLock } = useAuth();
            // a pinned layout (#1189) wins over the user's own, which stays stored
            const layout = layoutLock || user?.ui_layout || 'modern';
            const isCorporate = layout === 'corporate';
            // NS 2026-06-05 — Cloud skin (Preview). Third layout alongside modern/corporate.
            const isCloud = layout === 'cloud';

            // Set data-layout on body whenever layout changes
            // also force matching theme so modern themes dont bleed into corporate
            useEffect(() => {
                document.body.setAttribute('data-layout', layout);
                if (isCorporate) {
                    // LW Sep 2026 (#743) - applyTheme('system') resolves and sets the
                    // corp gate itself, so the stored choice wins over the local toggle
                    // here too. Anything else keeps the old path unchanged.
                    if (localStorage.getItem('pegaprox-theme') === 'system') {
                        applyTheme('system');
                    } else {
                    const isLight = localStorage.getItem('corp-theme') === 'light';
                    // MK May 2026 (#296): the data-corp-theme attribute gates ALL light-mode
                    // CSS overrides. The header toggle sets this on click, but on a fresh
                    // page load only applyTheme() ran — so light variables got applied but
                    // body still had no data-corp-theme, leaving every component in dark.
                    document.body.dataset.corpTheme = isLight ? 'light' : '';
                    applyTheme(isLight ? 'corporateLight' : 'corporateDark');
                    }
                } else if (isCloud) {
                    // NS: force the cloud theme on layout change + F5-restore so the
                    // teal/navy variables apply even if a stale theme was stored.
                    delete document.body.dataset.corpTheme;
                    applyTheme('cloud');
                } else {
                    // leaving corporate -> clear so no stale attribute lingers
                    delete document.body.dataset.corpTheme;
                }
            }, [layout]);

            // NS Jul 2026 (scale) — the corporate sidebar "show VM IDs" pref renders
            // the #vmid via a CSS ::after on each row (see index.html) instead of an
            // extra <span> per guest. Gate it with a single body flag so toggling the
            // pref costs nothing at 1000+ VMs (no per-row React re-render / DOM node).
            useEffect(() => {
                if (isCorporate && user?.sidebar_show_vmid) {
                    document.body.dataset.sidebarVmid = '1';
                } else {
                    delete document.body.dataset.sidebarVmid;
                }
            }, [isCorporate, user?.sidebar_show_vmid]);

            return { layout, isCorporate, isCloud, layoutLocked: !!layoutLock };
        }
