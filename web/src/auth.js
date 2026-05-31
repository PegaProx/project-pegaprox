        // ═══════════════════════════════════════════════
        // PegaProx - Authentication
        // LoginScreen component
        // ═══════════════════════════════════════════════
        
        // Login Screen Component
        // LW: Keep this simple - first thing users see!
        function LoginScreen() {
            const { t } = useTranslation();
            const { login, error, ldapEnabled, oidcEnabled, oidcButtonText, loginBackground } = useAuth();
            const [username, setUsername] = useState('');
            const [password, setPassword] = useState('');
            const [totpCode, setTotpCode] = useState('');
            const [loading, setLoading] = useState(false);
            const [showPassword, setShowPassword] = useState(false);
            const [requires2FA, setRequires2FA] = useState(false);
            // NS Apr 2026 — which 2FA methods are available for the user who just entered password
            const [twoFAMethods, setTwoFAMethods] = useState([]);
            const [webauthnBusy, setWebauthnBusy] = useState(false);
            const [rememberMe, setRememberMe] = useState(() => localStorage.getItem('pegaprox-remember') === 'true');
            
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
                            // NS: Apr 2026 - redirect to portal if OIDC flow was started from there
                            // LW May 2026 — backend filters strictly, but enforce the
                            // same rule client-side too: single leading /, not //
                            // (protocol-relative), no backslash, no control chars.
                            const ra = data.redirect_after;
                            if (ra && typeof ra === 'string' && ra.length < 200
                                && ra.charAt(0) === '/' && ra.charAt(1) !== '/' && ra.charAt(1) !== '\\'
                                && !/[\r\n\t\\]/.test(ra)) {
                                window.location.href = ra;
                                return;
                            }
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
                    if (data.auth_url && data.auth_url.startsWith('https://')) {
                        window.location.href = data.auth_url;
                    } else if (data.auth_url) {
                        // NS: Mar 2026 - block non-https redirects (open redirect prevention)
                        console.error('OIDC auth_url must use https');
                        setOidcError('Insecure authentication URL rejected');
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
                localStorage.setItem('pegaprox-remember', rememberMe);
                const result = await login(username, password, totpCode, rememberMe);

                if (result?.requires_2fa) {
                    setRequires2FA(true);
                    // server hints which 2FA methods the user has configured
                    if (Array.isArray(result.methods)) setTwoFAMethods(result.methods);
                }
                setLoading(false);
            };

            // NS Apr 2026 — WebAuthn flow for 2FA step. Hits /webauthn/auth/begin,
            // asks the browser, then /webauthn/auth/finish returns a one-shot proof
            // token we pipe into /auth/login so the session can be minted.
            const handleWebauthnLogin = async () => {
                if (!('credentials' in navigator) || !navigator.credentials.get) {
                    return;
                }
                setWebauthnBusy(true);
                try {
                    // helpers — same shape as create_modals.js but inline here to avoid a new import
                    const b64urlToBuf = (s) => {
                        const pad = '='.repeat((4 - s.length % 4) % 4);
                        const bin = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
                        const buf = new Uint8Array(bin.length);
                        for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
                        return buf.buffer;
                    };
                    const bufToB64url = (buf) => {
                        const bin = String.fromCharCode(...new Uint8Array(buf));
                        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                    };
                    const begin = await fetch(`${API_URL}/webauthn/auth/begin`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        credentials: 'include', body: JSON.stringify({ username })
                    });
                    if (!begin.ok) throw new Error((await begin.json().catch(() => ({}))).error || `begin ${begin.status}`);
                    const opts = await begin.json();
                    const pko = opts.publicKey || opts;
                    const publicKey = {
                        ...pko,
                        challenge: b64urlToBuf(pko.challenge),
                        allowCredentials: (pko.allowCredentials || []).map(c => ({ ...c, id: b64urlToBuf(c.id) })),
                    };
                    const assertion = await navigator.credentials.get({ publicKey });
                    if (!assertion) throw new Error('cancelled');
                    const finishBody = {
                        username,
                        id: assertion.id,
                        rawId: bufToB64url(assertion.rawId),
                        type: assertion.type,
                        response: {
                            clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
                            authenticatorData: bufToB64url(assertion.response.authenticatorData),
                            signature: bufToB64url(assertion.response.signature),
                            userHandle: assertion.response.userHandle ? bufToB64url(assertion.response.userHandle) : null,
                        },
                    };
                    const finish = await fetch(`${API_URL}/webauthn/auth/finish`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        credentials: 'include', body: JSON.stringify(finishBody)
                    });
                    const fd = await finish.json().catch(() => ({}));
                    if (!finish.ok || !fd.proof) throw new Error(fd.error || `finish ${finish.status}`);
                    // Now complete login with the proof
                    setLoading(true);
                    const result = await login(username, password, '', rememberMe, fd.proof);
                    setLoading(false);
                    if (result?.requires_2fa) setRequires2FA(true);  // shouldn't happen on success
                } catch (e) {
                    console.warn('webauthn login:', e);
                }
                setWebauthnBusy(false);
            };
            
            return(
                <div className="min-h-screen bg-proxmox-darker flex items-center justify-center p-4 relative"
                    style={loginBackground ? {
                        backgroundImage: `url(${loginBackground})`,
                        backgroundSize: 'cover',
                        backgroundPosition: 'center',
                        backgroundRepeat: 'no-repeat'
                    } : undefined}>
                    {loginBackground && (
                        <div className="absolute inset-0 bg-black/50" />
                    )}
                    <div className="w-full max-w-md relative z-10">
                        {/* Logo and Title */}
                        <div className="text-center mb-8">
                            <img
                                src="/images/pegaprox-logo-dark.png"
                                alt="PegaProx"
                                className="w-28 h-28 mx-auto mb-4 object-contain drop-shadow-[0_8px_20px_rgba(229,112,0,0.35)]"
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
                                    <div className="space-y-4">
                                        {twoFAMethods.includes('webauthn') && (
                                            <button type="button" onClick={handleWebauthnLogin} disabled={webauthnBusy}
                                                className="w-full flex items-center justify-center gap-3 px-4 py-3 bg-proxmox-dark hover:bg-proxmox-hover border border-proxmox-border rounded-xl text-white font-medium transition-colors disabled:opacity-50">
                                                {webauthnBusy ? <Icons.Loader className="w-5 h-5 animate-spin" /> : <Icons.Key className="w-5 h-5 text-proxmox-orange" />}
                                                {t('useSecurityKey') || 'Use Security Key'}
                                            </button>
                                        )}
                                        {twoFAMethods.includes('webauthn') && twoFAMethods.includes('totp') && (
                                            <div className="flex items-center gap-3">
                                                <div className="flex-1 h-px bg-proxmox-border"></div>
                                                <span className="text-xs text-gray-500 uppercase">{t('or') || 'or'}</span>
                                                <div className="flex-1 h-px bg-proxmox-border"></div>
                                            </div>
                                        )}
                                        {(twoFAMethods.length === 0 || twoFAMethods.includes('totp')) && (
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
                                    </div>
                                )}
                                
                                <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer select-none">
                                    <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} className="rounded border-gray-600 bg-proxmox-dark" />
                                    {t('rememberMe') || 'Remember me'}
                                </label>

                                {/* submit button: hidden when user only has WebAuthn (the Use Security Key button handles it) */}
                                {!(requires2FA && twoFAMethods.length === 1 && twoFAMethods[0] === 'webauthn') && (
                                    <button
                                        type="submit"
                                        disabled={loading || !username || !password || (requires2FA && twoFAMethods.includes('totp') && totpCode.length !== 6)}
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
                                )}
                            </form>
                            
                            {/* NS: Feb 2026 - OIDC / Entra ID login */}
                            {oidcEnabled && (
                                <div className="mt-4">
                                    <div className="flex items-center gap-3 mb-4">
                                        <div className="flex-1 h-px bg-proxmox-border"></div>
                                        <span className="text-xs text-gray-500 uppercase">or</span>
                                        <div className="flex-1 h-px bg-proxmox-border"></div>
                                    </div>
                                    {/* LW: #295 — detect provider from button text, show matching icon + color */}
                                    <button onClick={handleOidcLogin} disabled={oidcLoading}
                                        className={`w-full flex items-center justify-center gap-3 px-4 py-2.5 disabled:opacity-50 rounded-lg text-white font-medium text-sm transition-colors ${
                                            (oidcButtonText || '').toLowerCase().includes('microsoft') || (oidcButtonText || '').toLowerCase().includes('entra')
                                                ? 'bg-[#0078d4] hover:bg-[#106ebe]'
                                                : (oidcButtonText || '').toLowerCase().includes('google')
                                                    ? 'bg-white hover:bg-gray-100 text-gray-700 border border-gray-300'
                                                    : 'bg-proxmox-card hover:bg-proxmox-hover border border-proxmox-border'
                                        }`}>
                                        {oidcLoading ? (
                                            <Icons.Loader className="w-5 h-5 animate-spin" />
                                        ) : (oidcButtonText || '').toLowerCase().includes('microsoft') || (oidcButtonText || '').toLowerCase().includes('entra') ? (
                                            <svg className="w-5 h-5" viewBox="0 0 21 21" fill="none"><path d="M0 0h10v10H0z" fill="#f25022"/><path d="M11 0h10v10H11z" fill="#7fba00"/><path d="M0 11h10v10H0z" fill="#00a4ef"/><path d="M11 11h10v10H11z" fill="#ffb900"/></svg>
                                        ) : (
                                            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
                                        )}
                                        {oidcButtonText || 'Sign in with SSO'}
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

        // ═══════════════════════════════════════════════
        // First-Run Setup Wizard
        // MK May 2026 — replaces the hardcoded `pegaprox/admin` bootstrap that
        // exposed every fresh network-reachable install to remote takeover.
        // Renders instead of LoginScreen when /auth/check returns initialized=false.
        // ═══════════════════════════════════════════════
        function SetupWizard() {
            const [username, setUsername] = useState('');
            const [password, setPassword] = useState('');
            const [passwordConfirm, setPasswordConfirm] = useState('');
            const [displayName, setDisplayName] = useState('');
            const [email, setEmail] = useState('');
            const [showPassword, setShowPassword] = useState(false);
            const [submitting, setSubmitting] = useState(false);
            const [err, setErr] = useState('');
            const [done, setDone] = useState(false);

            const submit = async (e) => {
                e.preventDefault();
                setErr('');
                if (!username || username.length < 2) { setErr('Username must be at least 2 characters'); return; }
                if (username.toLowerCase() === 'pegaprox') { setErr("'pegaprox' is reserved — pick a different username"); return; }
                if (!password) { setErr('Password is required'); return; }
                if (password !== passwordConfirm) { setErr('Passwords do not match'); return; }
                setSubmitting(true);
                try {
                    const r = await fetch(`${API_URL}/auth/setup`, {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            username: username.trim().toLowerCase(),
                            password,
                            display_name: displayName,
                            email,
                        }),
                    });
                    const data = await r.json().catch(() => ({}));
                    if (!r.ok) {
                        setErr(data.error || `Setup failed (HTTP ${r.status})`);
                        setSubmitting(false);
                        return;
                    }
                    setDone(true);
                    // reload after a short delay so AuthProvider re-checks and shows the login form
                    setTimeout(() => window.location.reload(), 1500);
                } catch (e2) {
                    setErr('Network error — could not reach server');
                    setSubmitting(false);
                }
            };

            if (done) {
                return (
                    <div className="min-h-screen bg-proxmox-darker flex items-center justify-center p-4">
                        <div className="bg-proxmox-card border border-proxmox-border rounded-2xl p-8 shadow-xl max-w-md w-full text-center">
                            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-green-500/20 flex items-center justify-center">
                                <svg className="w-10 h-10 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                </svg>
                            </div>
                            <h2 className="text-xl font-semibold text-white mb-2">Setup complete</h2>
                            <p className="text-gray-400">Redirecting to login…</p>
                        </div>
                    </div>
                );
            }

            return (
                <div className="min-h-screen bg-proxmox-darker flex items-center justify-center p-4">
                    <div className="w-full max-w-md">
                        <div className="text-center mb-8">
                            <img
                                src="/images/pegaprox-logo-dark.png"
                                alt="PegaProx"
                                className="w-28 h-28 mx-auto mb-4 object-contain drop-shadow-[0_8px_20px_rgba(229,112,0,0.35)]"
                                onError={(e) => { e.target.style.display = 'none'; }}
                            />
                            <h1 className="text-3xl font-bold text-white mb-2">Welcome to PegaProx</h1>
                            <p className="text-gray-400">Create the first administrator account to get started</p>
                        </div>
                        <div className="bg-proxmox-card border border-proxmox-border rounded-2xl p-8 shadow-xl">
                            <h2 className="text-xl font-semibold text-white mb-6">First-Time Setup</h2>

                            {err && (
                                <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                                    {err}
                                </div>
                            )}

                            <form onSubmit={submit} className="space-y-5">
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">Username</label>
                                    <input
                                        type="text"
                                        value={username}
                                        onChange={(e) => setUsername(e.target.value)}
                                        className="w-full px-4 py-3 bg-proxmox-dark border border-proxmox-border rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors"
                                        placeholder="admin"
                                        autoComplete="username"
                                        autoFocus
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">Password</label>
                                    <div className="relative">
                                        <input
                                            type={showPassword ? 'text' : 'password'}
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            className="w-full px-4 py-3 bg-proxmox-dark border border-proxmox-border rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors pr-12"
                                            placeholder="••••••••"
                                            autoComplete="new-password"
                                        />
                                        <button
                                            type="button"
                                            onClick={() => setShowPassword(!showPassword)}
                                            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                                            tabIndex={-1}
                                        >
                                            {showPassword ? '🙈' : '👁'}
                                        </button>
                                    </div>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">Confirm password</label>
                                    <input
                                        type={showPassword ? 'text' : 'password'}
                                        value={passwordConfirm}
                                        onChange={(e) => setPasswordConfirm(e.target.value)}
                                        className="w-full px-4 py-3 bg-proxmox-dark border border-proxmox-border rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors"
                                        placeholder="••••••••"
                                        autoComplete="new-password"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">
                                        Display name <span className="text-gray-500 font-normal">(optional)</span>
                                    </label>
                                    <input
                                        type="text"
                                        value={displayName}
                                        onChange={(e) => setDisplayName(e.target.value)}
                                        className="w-full px-4 py-3 bg-proxmox-dark border border-proxmox-border rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors"
                                        placeholder="Cluster Admin"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">
                                        Email <span className="text-gray-500 font-normal">(optional)</span>
                                    </label>
                                    <input
                                        type="email"
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        className="w-full px-4 py-3 bg-proxmox-dark border border-proxmox-border rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-proxmox-orange transition-colors"
                                        placeholder="admin@example.com"
                                    />
                                </div>
                                <button
                                    type="submit"
                                    disabled={submitting}
                                    className="w-full px-4 py-3 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 rounded-xl text-white font-semibold transition-colors"
                                >
                                    {submitting ? 'Creating administrator…' : 'Create administrator'}
                                </button>
                            </form>

                            <p className="text-xs text-gray-500 mt-6 leading-relaxed">
                                This account becomes the first PegaProx administrator. Treat the
                                password like any other root credential — store it in your password
                                manager. You can create additional users (admin or scoped roles)
                                once you are logged in.
                            </p>
                        </div>
                        <p className="text-center text-gray-500 text-sm mt-6">
                            PegaProx Cluster Management {PEGAPROX_VERSION}
                        </p>
                    </div>
                </div>
            );
        }

