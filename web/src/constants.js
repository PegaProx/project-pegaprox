/**
 * PegaProx frontend constants.
 * API_URL: same origin - Flask serves both frontend and API.
 * PEGAPROX_VERSION: keep in sync with backend PEGAPROX_VERSION.
 */
export const API_URL = typeof window !== 'undefined' ? window.location.origin + '/api' : '';
export const PEGAPROX_VERSION = 'Beta 0.6.6';
export const DEBUG = false;
