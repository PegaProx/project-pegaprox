        // Keep API failures actionable without making every caller repeat the
        // response parsing. A missing or non-JSON response still gets the
        // caller's operation-specific fallback.
        const PegaProxApiErrors = {
            async message(response, fallback) {
                if (!response) return fallback;
                const body = await response.json().catch(() => null);
                const error = typeof body?.error === 'string' ? body.error.trim() : '';
                return error || fallback;
            },
            // LW Oct 2026 (#1142) - the codes PegaProx answers a 401 with when the session or
            // token of this browser is gone. A 401 without one is not ours to act on: it came
            // from a system behind PegaProx (an ESXi server with a changed password) or a proxy.
            SESSION_LOST: ['AUTH_REQUIRED', 'ACCOUNT_DELETED', 'ACCOUNT_DISABLED', 'INVALID_SESSION',
                           'INVALID_TOKEN', 'HA_FORWARD_STALE_SIGN_IN'],
            sessionLost(body) {
                return !!body && PegaProxApiErrors.SESSION_LOST.includes(body.code);
            }
        };
