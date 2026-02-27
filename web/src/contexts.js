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
            });

            return(
                <LanguageContext.Provider value={{ language, t, changeLanguage }}>
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
            
            return(
                <div className="flex items-center gap-1 bg-proxmox-dark rounded-lg p-1 border border-proxmox-border">
                    <button
                        onClick={() => changeLanguage('de')}
                        className={`flex items-center gap-1.5 px-2 py-1 rounded text-sm transition-all ${language === 'de' ? 'bg-proxmox-orange text-white' : 'text-gray-400 hover:text-white'}`}
                        title="Deutsch (Österreich)"
                    >
                        <span className="text-base">🇦🇹</span>
                        <span className="hidden sm:inline">DE</span>
                    </button>
                    <button
                        onClick={() => changeLanguage('en')}
                        className={`flex items-center gap-1.5 px-2 py-1 rounded text-sm transition-all ${language === 'en' ? 'bg-proxmox-orange text-white' : 'text-gray-400 hover:text-white'}`}
                        title="English"
                    >
                        <span className="text-base">🇬🇧</span>
                        <span className="hidden sm:inline">EN</span>
                    </button>
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
                        console.log('Session check response:', d);
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
                            // NS: Apply user's theme or default
                            const userTheme = d.user?.theme || d.default_theme || 'proxmoxDark';
                            console.log('[Theme] checkSession - Server theme:', d.user?.theme, 'Default:', d.default_theme, 'Using:', userTheme);
                            if (userTheme && PEGAPROX_THEMES[userTheme]) {
                                applyTheme(userTheme);
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
                        } catch(e) {}
                        logout();
                    }
                } catch (err) {
                    console.error('Session check failed:', err);
                    console.log('err obj:', err);
                    logout();
                }
                setLoading(false);
            };
            
            // -lw: Main login handler - supports 2FA flow
            // TODO: add "remember me" checkbox somtime
            const login = async (username, password, totpCode = '') => {
                setError(null);
                console.log('login attempt:', username);  // tmp debug
                try {
                    const resp = await fetch(`${API_URL}/auth/login`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password, totp_code: totpCode })
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
                        // NS: Apply user's theme (with fallback to default)
                        const userTheme = data.user?.theme || data.default_theme || 'proxmoxDark';
                        console.log('[Theme] Login - Server theme:', data.user?.theme, 'Default:', data.default_theme, 'Using:', userTheme);
                        if (userTheme && PEGAPROX_THEMES[userTheme]) {
                            applyTheme(userTheme);
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
                    console.log('updatePreferences: Sending request with prefs:', prefs);
                    const r = await fetch(`${API_URL}/user/preferences`, {
                        method: 'PUT',
                        credentials: 'include',
                        headers: { 
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(prefs)
                    });
                    console.log('updatePreferences: Response status:', r.status);
                    
                    if (r.ok) {
                        const data = await r.json();
                        console.log('updatePreferences: Response data:', data);
                        
                        // Update user in state
                        setUser(currentUser => {
                            const updated = {
                                ...currentUser,
                                theme: data.theme,
                                language: data.language,
                                ui_layout: data.ui_layout,
                                taskbar_auto_expand: data.taskbar_auto_expand
                            };
                            console.log('updatePreferences: Updated user state:', updated);
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
                <AuthContext.Provider value={{ user, sessionId, isAuthenticated, loading, error, login, logout, getAuthHeaders, isAdmin: user?.role === 'admin', passwordExpiry, requires2FASetup, setRequires2FASetup, updatePreferences, ldapEnabled, oidcEnabled, oidcButtonText }}>
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
