        // ═══════════════════════════════════════════════
        // PegaProx - Authentication
        // LoginScreen component
        // ═══════════════════════════════════════════════
        
        // Login Screen Component
        // LW: Keep this simple - first thing users see!
        function LoginScreen() {
            const { t } = useTranslation();
            const { login, error, ldapEnabled, oidcEnabled, oidcButtonText } = useAuth();
            const [username, setUsername] = useState('');
            const [password, setPassword] = useState('');
            const [totpCode, setTotpCode] = useState('');
            const [loading, setLoading] = useState(false);
            const [showPassword, setShowPassword] = useState(false);
            const [requires2FA, setRequires2FA] = useState(false);
            
            const [oidcLoading, setOidcLoading] = useState(false);
            
            // NS: Feb 2026 - Handle OIDC callback (check URL for auth code on mount)
            React.useEffect(() => {
                const params = new URLSearchParams(window.location.search);
                const code = params.get('code');
                const state = params.get('state');
                if (code && state) {
                    // We got redirected back from IdP with auth code
                    setOidcLoading(true);
                    fetch(`${API_URL}/auth/oidc/callback`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ code, state })
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            // Clear URL params and reload to authenticated state
                            window.history.replaceState({}, '', window.location.pathname);
                            window.location.reload();
                        } else {
                            setOidcError(data.error || 'OIDC authentication failed');
                            window.history.replaceState({}, '', window.location.pathname);
                        }
                    })
                    .catch(() => { setOidcError('Network error during OIDC callback'); })
                    .finally(() => setOidcLoading(false));
                }
            }, []);
            
            const [oidcError, setOidcError] = useState('');
            
            const handleOidcLogin = async () => {
                setOidcLoading(true);
                setOidcError('');
                try {
                    const res = await fetch(`${API_URL}/auth/oidc/authorize`, { credentials: 'include' });
                    const data = await res.json();
                    if (data.auth_url) {
                        window.location.href = data.auth_url;
                    } else {
                        setOidcError(data.error || 'Failed to get authorization URL');
                        setOidcLoading(false);
                    }
                } catch (e) {
                    setOidcError('Network error');
                    setOidcLoading(false);
                }
            };
            
            const handleSubmit = async (e) => {
                e.preventDefault();
                if (!username || !password) return;
                if (requires2FA && !totpCode) return;
                
                setLoading(true);
                const result = await login(username, password, totpCode);
                
                if (result?.requires_2fa) {
                    setRequires2FA(true);
                }
                setLoading(false);
            };
            
            return(
                <div className="min-h-screen bg-proxmox-darker flex items-center justify-center p-4">
                    <div className="w-full max-w-md">
                        {/* Logo and Title */}
                        <div className="text-center mb-8">
                            <img 
                                src="/images/pegaprox.png" 
                                alt="PegaProx" 
                                className="w-24 h-24 mx-auto mb-4 rounded-full object-cover shadow-lg shadow-orange-500/30"
                                onError={(e) => {
                                    // fallback to styled div if PNG not found
                                    e.target.outerHTML = '<div class="w-24 h-24 mx-auto mb-4 rounded-full bg-gradient-to-br from-proxmox-orange to-orange-600 flex items-center justify-center shadow-lg shadow-orange-500/30"><svg class="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" /></svg></div>';
                                }}
                            />
                            <h1 className="text-3xl font-bold text-white mb-2">PegaProx</h1>
                            <p className="text-gray-400">{t('loginSubtitle')}</p>
                        </div>
                        
                        {/* Login Form */}
                        <div className="bg-proxmox-card border border-proxmox-border rounded-2xl p-8 shadow-xl">
                            <h2 className="text-xl font-semibold text-white mb-6">
                                {requires2FA ? t('twoFARequired') : t('loginTitle')}
                            </h2>
                            
                            {error && (
                                <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                                    {error}
                                </div>
                            )}
                            
                            <form onSubmit={handleSubmit} className="space-y-5">
                                {!requires2FA ? (
                                    <>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-300 mb-2">
                                                {t('usernameLabel')}
                                            </label>
                                            <input
                                                type="text"
                                                value={username}
                                                onChange={(e) => setUsername(e.target.value)}
                                                className="w-full px-4 py-3 bg-proxmox-dark border border-proxmox-border rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors"
                                                placeholder="pegaprox"
                                                autoComplete="username"
                                                autoFocus
                                            />
                                        </div>
                                        
                                        <div>
                                            <label className="block text-sm font-medium text-gray-300 mb-2">
                                                {t('passwordLabel')}
                                            </label>
                                            <div className="relative">
                                                <input
                                                    type={showPassword ? 'text' : 'password'}
                                                    value={password}
                                                    onChange={(e) => setPassword(e.target.value)}
                                                    className="w-full px-4 py-3 bg-proxmox-dark border border-proxmox-border rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors pr-12"
                                                    placeholder="••••••••"
                                                    autoComplete="current-password"
                                                />
                                                <button
                                                    type="button"
                                                    onClick={() => setShowPassword(!showPassword)}
                                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                                                >
                                                    {showPassword ? (
                                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                                                        </svg>
                                                    ) : (
                                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                                        </svg>
                                                    )}
                                                </button>
                                            </div>
                                        </div>
                                    </>
                                ) : (
                                    <div>
                                        <label className="block text-sm font-medium text-gray-300 mb-2">
                                            {t('enter2FACode')}
                                        </label>
                                        <input
                                            type="text"
                                            value={totpCode}
                                            onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                            className="w-full px-4 py-3 bg-proxmox-dark border border-proxmox-border rounded-xl text-white text-center text-2xl tracking-widest placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors"
                                            placeholder="000000"
                                            maxLength={6}
                                            autoFocus
                                        />
                                        <p className="text-gray-400 text-sm mt-2 text-center">
                                            {t('scan2FACode')}
                                        </p>
                                    </div>
                                )}
                                
                                <button
                                    type="submit"
                                    disabled={loading || !username || !password}
                                    className="w-full py-3 bg-proxmox-orange rounded-xl text-white font-semibold hover:bg-orange-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                                >
                                    {loading ? (
                                        <>
                                            <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                            </svg>
                                            {t('loggingIn')}
                                        </>
                                    ) : (
                                        t('loginButton')
                                    )}
                                </button>
                            </form>
                            
                            {/* NS: Feb 2026 - OIDC / Entra ID login */}
                            {oidcEnabled && (
                                <div className="mt-4">
                                    <div className="flex items-center gap-3 mb-4">
                                        <div className="flex-1 h-px bg-proxmox-border"></div>
                                        <span className="text-xs text-gray-500 uppercase">or</span>
                                        <div className="flex-1 h-px bg-proxmox-border"></div>
                                    </div>
                                    <button onClick={handleOidcLogin} disabled={oidcLoading}
                                        className="w-full flex items-center justify-center gap-3 px-4 py-2.5 bg-[#0078d4] hover:bg-[#106ebe] disabled:opacity-50 rounded-lg text-white font-medium text-sm transition-colors">
                                        {oidcLoading ? (
                                            <Icons.Loader className="w-5 h-5 animate-spin" />
                                        ) : (
                                            <svg className="w-5 h-5" viewBox="0 0 21 21" fill="none"><path d="M0 0h10v10H0z" fill="#f25022"/><path d="M11 0h10v10H11z" fill="#7fba00"/><path d="M0 11h10v10H0z" fill="#00a4ef"/><path d="M11 11h10v10H11z" fill="#ffb900"/></svg>
                                        )}
                                        {oidcButtonText || 'Sign in with Microsoft'}
                                    </button>
                                    {oidcError && (
                                        <p className="text-red-400 text-xs text-center mt-2">{oidcError}</p>
                                    )}
                                </div>
                            )}
                            
                            {/* MK: Feb 2026 - LDAP indicator */}
                            {ldapEnabled && (
                                <div className="mt-3 flex items-center justify-center gap-2 text-xs text-gray-500">
                                    <Icons.Users className="w-3 h-3" />
                                    <span>LDAP / Active Directory enabled</span>
                                </div>
                            )}
                        </div>
                        
                        {/* Language Switcher */}
                        <div className="flex justify-center mt-6">
                            <LanguageSwitcher />
                        </div>
                        
                        {/* Footer */}
                        <p className="text-center text-gray-500 text-sm mt-6">
                            PegaProx Cluster Management {PEGAPROX_VERSION}
                        </p>
                    </div>
                </div>
            );
        }

