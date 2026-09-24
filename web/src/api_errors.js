        // Keep API failures actionable without making every caller repeat the
        // response parsing. A missing or non-JSON response still gets the
        // caller's operation-specific fallback.
        const PegaProxApiErrors = {
            async message(response, fallback) {
                if (!response) return fallback;
                const body = await response.json().catch(() => null);
                const error = typeof body?.error === 'string' ? body.error.trim() : '';
                return error || fallback;
            }
        };
