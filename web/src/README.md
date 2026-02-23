# PegaProx frontend source

- `main.jsx` – Entry point, mounts Root with React 18 createRoot.
- `App.jsx` – Main app (contexts, translations, all UI components). To be split incrementally into `components/`, `screens/`, `i18n/`, etc.
- `constants.js` – API_URL, PEGAPROX_VERSION, DEBUG.
- `index.css` – Tailwind + global styles.

Build: `npm run build` (output in `web/dist/`). Dev: `npm run dev`.
