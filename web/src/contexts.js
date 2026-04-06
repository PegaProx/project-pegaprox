        // ═══════════════════════════════════════════════
        // PegaProx - Contexts
        // LanguageContext + AuthContext providers
        // ═══════════════════════════════════════════════
        // Language Context
        // LW: Default is German (de) since thats what we use internally
        const LanguageContext = createContext();

        function LanguageProvider({ children }) {
            // Persist language preference in localStorage
            const [language, setLanguage] = useState(() => {
                const saved = localStorage.getItem('pegaprox-language');
                return saved || 'de';  // German default
            });

            // Translation function with English fallback
            const t = useCallback((key) => {
                return translations[language]?.[key] || translations['en']?.[key] || key;
            }, [language]);

            const changeLanguage = useCallback((lang) => {
                setLanguage(lang);
                localStorage.setItem('pegaprox-language', lang);
                // persist to server so other devices pick it up
                fetch(`${API_URL}/user/preferences`, {
                    method: 'PUT', credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ language: lang })
                }).catch(() => {}); // fire and forget
            });

            // applyLanguage just sets state+localStorage without API call (used on login/session restore)
            const applyLanguage = useCallback((lang) => {
                setLanguage(lang);
                localStorage.setItem('pegaprox-language', lang);
            }, []);

            return(
                <LanguageContext.Provider value={{ language, t, changeLanguage, applyLanguage }}>
                    {children}
                </LanguageContext.Provider>
            );
        }

        function useTranslation() {
            return useContext(LanguageContext);
        }

        // Language Switcher Component
        function LanguageSwitcher() {
            const { language, changeLanguage } = useTranslation();
            const { isCorporate } = useLayout();
            const langs = [
                { code: 'de', flag: '🇦🇹', label: 'DE', title: 'Deutsch' },
                { code: 'en', flag: '🇬🇧', label: 'EN', title: 'English' },
                { code: 'fr', flag: '🇫🇷', label: 'FR', title: 'Français' },
                { code: 'es', flag: '🇪🇸', label: 'ES', title: 'Español (LATAM)' },
                { code: 'pt', flag: '🇧🇷', label: 'PT', title: 'Português' },
                { code: 'ko', flag: '🇰🇷', label: 'KO', title: '한국어' },
            ];
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
                            onChange={(e) => changeLanguage(e.target.value)}
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
                            onClick={() => !l.soon && changeLanguage(l.code)}
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
        
        function AuthProvider({ children }) {
            const { applyLanguage } = useTranslation();
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
            const [oidcButtonText, setOidcButtonText] = useState('Sign in with Microsoft');
            const [loginBackground, setLoginBackground] = useState('');
            const [reverseProxyEnabled, setReverseProxyEnabled] = useState(false);
            
            // Check session on mount
            useEffect(() => {
                checkSession();
            }, []);
            
            // check if session still valid (cookie is sent automatically)
            const checkSession = async () => {
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
                        if (d.authenticated) {
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
                            const userTheme = d.user?.theme || d.default_theme || 'proxmoxDark';
                            console.log('[Theme] checkSession - Server theme:', d.user?.theme, 'Default:', d.default_theme, 'Using:', userTheme);
                            if (userTheme && PEGAPROX_THEMES[userTheme]) {
                                applyTheme(userTheme);
                            }
                            // NS: Store reverse proxy status
                            if (d.reverse_proxy_enabled !== undefined) {
                                setReverseProxyEnabled(d.reverse_proxy_enabled);
                            }
                        } else {
                            logout();
                        }
                    } else {
                        // NS: Feb 2026 - Capture ldap_enabled from 401 response
                        try {
                            const errData = await r.json();
                            if (errData.ldap_enabled !== undefined) setLdapEnabled(errData.ldap_enabled);
                            if (errData.oidc_enabled !== undefined) { setOidcEnabled(errData.oidc_enabled); setOidcButtonText(errData.oidc_button_text || 'Sign in with Microsoft'); }
                            if (errData.login_background) setLoginBackground(errData.login_background);
                            if (errData.reverse_proxy_enabled !== undefined) setReverseProxyEnabled(errData.reverse_proxy_enabled);
                        } catch(e) {}
                        logout();
                    }
                } catch (err) {
                    console.error('Session check failed');
                    logout();
                }
                setLoading(false);
            };
            
            // -lw: Main login handler - supports 2FA flow + remember me
            const login = async (username, password, totpCode = '', remember = false) => {
                setError(null);
                try {
                    const resp = await fetch(`${API_URL}/auth/login`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password, totp_code: totpCode, remember })
                    });
                    
                    const data = await resp.json();
                    
                    // rate limit check
                    if (resp.status === 429 && data.locked) {
                        setError(`${data.error}`);
                        return { success: false, locked: true, retry_after: data.retry_after };
                    }
                    
                    // 2fa required?
                    if (resp.ok && data.requires_2fa) {
                        return { requires_2fa: true };
                    }
                    
                    if (resp.ok && data.success) {
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
                        const userTheme = data.user?.theme || data.default_theme || 'proxmoxDark';
                        console.log('[Theme] Login - Server theme:', data.user?.theme, 'Default:', data.default_theme, 'Using:', userTheme);
                        if (userTheme && PEGAPROX_THEMES[userTheme]) {
                            applyTheme(userTheme);
                        }
                        // NS: Store reverse proxy status
                        if (data.reverse_proxy_enabled !== undefined) {
                            setReverseProxyEnabled(data.reverse_proxy_enabled);
                        }
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
                                layout_chosen: data.layout_chosen
                            };
                            // LW: state updated, no log needed
                            return updated;
                        });
                        
                        // Apply theme immediately AND save to localStorage
                        if (data.theme && PEGAPROX_THEMES[data.theme]) {
                            applyTheme(data.theme);
                        }
                        return { success: true, data };
                    }
                    
                    const errorData = await r.json().catch(() => ({}));
                    console.error('updatePreferences: Request failed:', errorData);
                    return { success: false, error: errorData.error };
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
                        credentials: 'include'  // Cookie is sent automatically
                    });
                } catch (err) {
                    console.error('Logout request failed:', err);
                }
                setUser(null);
                setSessionId(null);
                setIsAuthenticated(false);
            };
            
            // NS: No more X-Session-ID header needed for fetch - cookies are automatic
            // But sessionId is still available for WebSocket URLs
            const getAuthHeaders = () => {
                return {};  // Empty - credentials: 'include' handles auth for fetch
            };
            
            return(
                <AuthContext.Provider value={{ user, sessionId, isAuthenticated, loading, error, login, logout, getAuthHeaders, isAdmin: user?.role === 'admin', passwordExpiry, requires2FASetup, setRequires2FASetup, updatePreferences, updateCurrentUser, ldapEnabled, oidcEnabled, oidcButtonText, loginBackground, reverseProxyEnabled }}>
                    {children}
                </AuthContext.Provider>
            );
        }
        
        function useAuth() {
            return useContext(AuthContext);
        }

        // LW: Feb 2026 - layout hook (reads from user preferences)
        // returns layout type and convenience boolean for corporate mode
        function useLayout() {
            const { user } = useAuth();
            const layout = user?.ui_layout || 'modern';
            const isCorporate = layout === 'corporate';

            // Set data-layout on body whenever layout changes
            useEffect(() => {
                document.body.setAttribute('data-layout', layout);
            }, [layout]);

            return { layout, isCorporate };
        }
