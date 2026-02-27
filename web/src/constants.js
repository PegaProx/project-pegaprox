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
        const PEGAPROX_VERSION = "Beta 0.9.0.2";
        const DEBUG = false; // set true for verbose logging

        // =====================================================
        // TRANSLATION SYSTEM
        // LW: German first because thats what we started with
        // English added later. Some keys might still be missing
        // TODO: Maybe add French/Spanish someday?
        // FIXME: some keys are definetly duplicated, cleanup needed
        // =====================================================
