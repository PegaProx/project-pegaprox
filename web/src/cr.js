        // ═══════════════════════════════════════════════════════════
        // Corporate Layout - Redesigned - LW Oct 2026
        // The pieces of the redesigned Corporate skin. Only rendered where
        // useLayout().isCorpRedesigned holds, so classic Corporate, Modern and
        // Cloud never mount any of it. The look lives in the one cr-* block at
        // the end of the stylesheet in index.html.original.
        // ═══════════════════════════════════════════════════════════

        // storage that never throws: a private window or blocked site data reads as nothing
        function crRead(key) {
            try { return localStorage.getItem(key); } catch (_) { return null; }
        }
        function crWrite(key, value) {
            try {
                if (value == null) localStorage.removeItem(key);
                else localStorage.setItem(key, String(value));
            } catch (_) {}
        }
        function crReadJson(key) {
            const raw = crRead(key);
            if (!raw) return null;
            try {
                const v = JSON.parse(raw);
                return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
            } catch (_) { return null; }
        }
        function crClamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }
        // t() answers the key itself for a key no language has: the fallback is said then
        function crTOr(t, key, fallback) {
            const v = t(key);
            return v && v !== key ? v : fallback;
        }

        // LW Nov 2026 - what a module store of the redesign holds was read by one account. A logout
        // does not reload the page and the next account may see less, so each store says how it
        // empties itself and its hook asks crSessionFor(user) before the store is read. gen tells
        // an answer that comes back for the account before; it is dropped
        const crSession = { who: null, gen: 0, resets: [] };
        function crSessionStore(reset) { crSession.resets.push(reset); }
        function crSessionFor(user) {
            const who = (user && user.username) || '';
            if (crSession.who !== who) {
                if (crSession.who !== null) crSession.resets.forEach(fn => { try { fn(); } catch (_) {} });
                crSession.who = who;
                crSession.gen++;
            }
            return crSession.gen;
        }

        // focus back where a dialog was opened; when that control got disabled meanwhile (a check
        // that runs now) its nearest [data-cr-focus-home] takes it, not the page
        function crFocusBack(el) {
            if (!el || !el.isConnected || !el.focus) return;
            if (!el.disabled) {
                el.focus({ preventScroll: true });
                if (document.activeElement === el) return;
            }
            const home = el.closest && el.closest('[data-cr-focus-home]');
            if (home) home.focus({ preventScroll: true });
        }

        // the sidebar of the redesign: its own keys, so switching layouts never moves the classic one
        // liveRows: up to this many tree rows the sidebar follows the drag live
        const CR_SIDEBAR = { min: 180, max: 520, def: 264, rail: 44, liveRows: 1500 };
        function crSidebarWidth() {
            const n = parseInt(crRead('cr-sidebar-w'), 10);
            return Number.isFinite(n) ? crClamp(n, CR_SIDEBAR.min, CR_SIDEBAR.max) : CR_SIDEBAR.def;
        }

        // LW Nov 2026 - numbers and dates of the redesign go by the UI language, not by the browser:
        // a German browser must not put "17,4 Mrd." next to "7.1 TB" in an English page. crLocale()
        // is the one place that turns a UI language into its BCP 47 tag, every toLocale*String and
        // Intl formatter of the cr files is handed it. PegaProxDashboard tells the language it draws
        // in (crUiLocale) before the views below it render, so a helper outside a component has it too
        const CR_LOCALE_TAGS = { de: 'de', en: 'en', zh: 'zh-CN', pl: 'pl', fr: 'fr', es: 'es', pt: 'pt', ko: 'ko', it: 'it', ru: 'ru' };
        const crUi = { lang: 'en' };
        function crUiLocale(lang) {
            if (CR_LOCALE_TAGS[lang]) crUi.lang = lang;
        }
        function crLocale(lang = crUi.lang) {
            return CR_LOCALE_TAGS[lang] || 'en';
        }
        // fmtDate, fmtTime and fmtClock of constants.js in the UI language: the same parts and the
        // same 12h/24h setting, only the locale is ours. crRead never throws, blocked site data included
        const CR_DTF_PARTS = {
            D: { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' },
            T: { hour: '2-digit', minute: '2-digit', second: '2-digit' },
            M: { hour: '2-digit', minute: '2-digit' },
        };
        const crDtfMade = {};
        function crDtf(kind, d, opts) {
            if (!d) return '';
            const dt = d instanceof Date ? d : new Date(typeof d === 'number' && d < 1e12 ? d * 1000 : d);
            if (isNaN(dt)) return '';
            const loc = crLocale();
            // a part given as undefined is left out, by Intl and by the key alike
            const o = { ...CR_DTF_PARTS[kind], hour12: crRead('pegaprox-time-format') === '12h', ...(opts || {}) };
            const key = `${loc}|${JSON.stringify(o)}`;
            let f = crDtfMade[key];
            if (!f) {
                try { f = new Intl.DateTimeFormat(loc, o); }
                catch (_) { f = new Intl.DateTimeFormat(loc); }
                crDtfMade[key] = f;
            }
            return f.format(dt);
        }
        const crFmtDate = (d, opts) => crDtf('D', d, opts);
        const crFmtTime = (d) => crDtf('T', d, null);
        const crFmtClock = (d, opts) => crDtf('M', d, opts);

        // --- small building blocks ----------------------------------------------

        function CrBadge({ tone = 'neutral', dot = true, title, children }) {
            return (
                <span className={`cr-badge cr-badge-${tone}${dot ? '' : ' cr-badge-plain'}`} title={title}>{children}</span>
            );
        }

        function CrButton({ variant = 'default', icon, children, className = '', ...rest }) {
            return (
                <button type="button" className={`cr-btn cr-btn-${variant}${children ? '' : ' cr-btn-icon'} ${className}`} {...rest}>
                    {icon && <span className="cr-ico" aria-hidden="true">{icon}</span>}
                    {children}
                </button>
            );
        }

        function CrPanel({ title, actions, children, className = '', bodyClassName = '', ...rest }) {
            return (
                <section className={`cr-panel ${className}`} {...rest}>
                    {(title || actions) && (
                        <header className="cr-panel-header">
                            <h3 className="cr-panel-title">{title}</h3>
                            {actions && <div className="cr-panel-actions">{actions}</div>}
                        </header>
                    )}
                    <div className={`cr-panel-body ${bodyClassName}`}>{children}</div>
                </section>
            );
        }

        // --- CrBoundary ---------------------------------------------------------
        // Around a page of the redesign: an answer of a shape the page does not expect stops that
        // page with a note, not the whole app. Retry draws it again from the same props.
        function CrBoundaryNote({ id, error, onRetry }) {
            const { t } = useTranslation();
            const text = error && error.message ? String(error.message).slice(0, 300) : '';
            return (
                <div className="cr-callout cr-callout-error cr-boundary" role="alert" data-cr-boundary={id || ''}>
                    <Icons.AlertCircle className="w-4 h-4" />
                    <div>
                        <p className="cr-strong">{t('crBoundaryTitle')}</p>
                        <p className="cr-muted">{t('crBoundaryHint')}{text ? ` (${text})` : ''}</p>
                    </div>
                    <button type="button" className="cr-btn cr-btn-xs" onClick={onRetry} data-cr-boundary-retry="">{t('retry')}</button>
                </div>
            );
        }
        class CrBoundary extends React.Component {
            constructor(props) {
                super(props);
                this.state = { error: null };
            }
            static getDerivedStateFromError(error) { return { error }; }
            componentDidCatch(error) { console.warn('[cr] a view could not be drawn:', error && error.message); }
            render() {
                if (!this.state.error) return this.props.children;
                return <CrBoundaryNote id={this.props.id} error={this.state.error} onRetry={() => this.setState({ error: null })} />;
            }
        }

        // --- CrSidePanel --------------------------------------------------------
        // The detail panel on the right, one for every module of the redesign. It sits between the
        // header and the bottom bars, so the task bar stays reachable, and it is not modal: the
        // page behind stays usable and the next row opens in the same panel. Opening moves the
        // focus into it (again when focusKey changes), closing hands it back to where it came from
        // (returnFocus() when that element is gone). Escape closes it, unless the task center, an
        // open menu or another dialog had the key first.
        let crPanelSeq = 0;
        // a fixed element that covers most of the window (a classic modal and its backdrop)
        function crInOverlay(el) {
            for (let n = el; n && n !== document.body; n = n.parentElement) {
                if (getComputedStyle(n).position !== 'fixed') continue;
                const r = n.getBoundingClientRect();
                if (r.width >= window.innerWidth * 0.9 && r.height >= window.innerHeight * 0.9) return true;
            }
            return false;
        }
        function CrSidePanel({ open, id, title, sub, onClose, footer, children, focusKey, returnFocus, label }) {
            const { t } = useTranslation();
            const ref = useRef(null);
            const back = useRef(null);
            const [titleId] = useState(() => `cr-sp-title-${++crPanelSeq}`);
            const closeRef = useRef(onClose);
            closeRef.current = onClose;
            const returnRef = useRef(returnFocus);
            returnRef.current = returnFocus;

            const wasOpen = useRef(false);
            useEffect(() => {
                if (!open) return;
                wasOpen.current = true;
                const a = document.activeElement;
                if (a && a !== document.body && !(ref.current && ref.current.contains(a))) back.current = a;
                if (ref.current) ref.current.focus({ preventScroll: true });
            }, [open, focusKey]);
            useEffect(() => {
                if (open || !wasOpen.current) return;
                wasOpen.current = false;
                let to = back.current;
                back.current = null;
                if (!to || !to.isConnected) to = returnRef.current ? returnRef.current() : null;
                if (to && typeof to.focus === 'function') to.focus({ preventScroll: true });
            }, [open]);
            useEffect(() => {
                if (!open) return undefined;
                const onKey = (e) => {
                    if (e.key !== 'Escape' || e.defaultPrevented) return;
                    const el = e.target && e.target.closest ? e.target : null;
                    const mine = !!(el && ref.current && ref.current.contains(el));
                    if (el && el.closest('.cr-taskcenter, .cr-tc-layer, .cr-menu, [role="menu"], [role="listbox"]')) return;
                    const dlg = el && el.closest('[role="dialog"], [role="alertdialog"]');
                    if (dlg && dlg !== ref.current) return;
                    // the classic dialogs have no role: a fixed layer over the page is one of them. The focus
                    // can also be left on the page while one covers it (a click on its text)
                    if (!mine) {
                        if (el && crInOverlay(el)) return;
                        const top = document.elementFromPoint(window.innerWidth / 2, window.innerHeight / 2);
                        if (top && !(ref.current && ref.current.contains(top)) && crInOverlay(top)) return;
                    }
                    // a search box outside clears itself first
                    if (!mine && el && el.tagName === 'INPUT' && el.value) return;
                    e.preventDefault();
                    closeRef.current();
                };
                document.addEventListener('keydown', onKey);
                return () => document.removeEventListener('keydown', onKey);
            }, [open]);

            if (!open) return null;
            return ReactDOM.createPortal(
                <div className="cr-sidepanel" role="dialog" aria-modal="false" aria-labelledby={label ? undefined : titleId}
                    aria-label={label} tabIndex={-1} ref={ref} data-cr-sidepanel={id || ''}>
                    <header className="cr-sp-head">
                        <div className="cr-sp-titles">
                            <h2 className="cr-sp-title" id={titleId}>{title}</h2>
                            {sub && <div className="cr-sp-sub">{sub}</div>}
                        </div>
                        <button type="button" className="cr-icon-btn" onClick={() => closeRef.current()} data-cr-sp-close=""
                            aria-label={t('close')} title={`${t('close')} (Esc)`}>
                            <span className="cr-ico" aria-hidden="true"><Icons.X /></span>
                        </button>
                    </header>
                    <div className="cr-sp-body">{children}</div>
                    {footer && <footer className="cr-sp-foot">{footer}</footer>}
                </div>,
                document.body
            );
        }

        // --- CrTable ------------------------------------------------------------
        // A dense table for every list of the redesign. Columns:
        //   { key, label, menuLabel, width, min, flex, align, mono, sortable, resizable,
        //     hidden, sortValue(row), text(row), render(row), title }
        // Widths and hidden columns are kept per id in localStorage. Above 200 rows only the
        // rows in view (plus a margin) are in the DOM; they stay real <tr> of a fixed height.
        // renderExpanded(row) draws a detail row under each row whose key is set in expanded
        // ({key: true}); while one is open the table is not virtualized.

        const CR_VIRTUAL_FROM = 200;

        function crCompare(a, b) {
            if (typeof a === 'number' && typeof b === 'number') return a - b;
            return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
        }
        const crEmpty = (v) => v == null || v === '' || (typeof v === 'number' && !Number.isFinite(v));

        function CrTable({ id, columns, rows, rowKey, onRowClick, onRowContextMenu, rowClassName, selectedKey,
                           filter, searchable = false, searchPlaceholder, toolbar, actions, loading = false, error = null,
                           emptyText, rowHeight = 26, maxHeight, virtualize, initialSort = null, ariaLabel,
                           columnMenu = true, showCount = true, expanded, renderExpanded }) {
            const { t } = useTranslation();
            const storeKey = id ? `cr-table:${id}` : null;
            const [prefs, setPrefs] = useState(() => (storeKey && crReadJson(storeKey)) || {});
            const prefsRef = useRef(prefs);
            prefsRef.current = prefs;
            const [sort, setSort] = useState(initialSort);
            const [query, setQuery] = useState('');
            const [menuOpen, setMenuOpen] = useState(false);
            const [scrollTop, setScrollTop] = useState(0);
            const [viewH, setViewH] = useState(maxHeight || 600);
            const [focusIdx, setFocusIdx] = useState(0);
            const scrollRef = useRef(null);
            const headRef = useRef(null);
            const bodyRef = useRef(null);
            // the row index a keyboard move still has to focus (null: none)
            const wantFocus = useRef(null);

            const widths = prefs.w || {};
            const hidden = prefs.h || {};
            const keep = (next) => {
                setPrefs(next);
                if (storeKey) crWrite(storeKey, Object.keys(next).length ? JSON.stringify(next) : null);
            };
            const isHidden = (c) => (Object.prototype.hasOwnProperty.call(hidden, c.key) ? !!hidden[c.key] : !!c.hidden);
            const visible = columns.filter(c => !isHidden(c));
            const widthOf = (c) => widths[c.key] || (c.flex ? null : c.width) || null;

            const all = Array.isArray(rows) ? rows : [];
            const shown = useMemo(() => {
                let list = typeof filter === 'function' ? all.filter(filter) : all;
                const q = query.trim().toLowerCase();
                if (q) {
                    list = list.filter(r => columns.some(c => {
                        const v = c.text ? c.text(r) : (c.sortValue ? c.sortValue(r) : r[c.key]);
                        return v != null && String(v).toLowerCase().includes(q);
                    }));
                }
                const col = sort && columns.find(c => c.key === sort.key);
                if (col) {
                    const val = col.sortValue || (r => r[col.key]);
                    const dir = sort.dir === 'desc' ? -1 : 1;
                    // empty values stay at the end whichever way it sorts
                    list = list.map((r, i) => [r, val(r), i]).sort((x, y) => {
                        const xe = crEmpty(x[1]), ye = crEmpty(y[1]);
                        if (xe || ye) return xe === ye ? x[2] - y[2] : (xe ? 1 : -1);
                        return (crCompare(x[1], y[1]) * dir) || (x[2] - y[2]);
                    }).map(x => x[0]);
                }
                return list;
            }, [all, filter, query, sort, columns]);

            const opened = (k) => !!(renderExpanded && expanded && expanded[k]);
            const anyOpen = !!(renderExpanded && expanded && Object.keys(expanded).some(k => expanded[k]));
            const virtual = shown.length > 0 && !anyOpen && (virtualize != null ? virtualize : shown.length > CR_VIRTUAL_FROM);
            const overscan = 10;
            let start = 0;
            let end = shown.length;
            if (virtual) {
                start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
                end = Math.min(shown.length, Math.ceil((scrollTop + viewH) / rowHeight) + overscan);
            }
            const fi = Math.min(focusIdx, Math.max(0, shown.length - 1));

            const measure = () => {
                const el = scrollRef.current;
                if (!el) return;
                setScrollTop(el.scrollTop);
                if (el.clientHeight) setViewH(el.clientHeight);
            };
            useEffect(() => {
                measure();
                if (typeof ResizeObserver === 'undefined' || !scrollRef.current) return;
                const ro = new ResizeObserver(() => measure());
                ro.observe(scrollRef.current);
                return () => ro.disconnect();
            }, []);
            // a keyboard move lands focus on the row once it is rendered. LW Nov 2026 - the target
            // sits in the ref, not in this render's fi: an effect of an earlier render can still be
            // pending when the key comes (a menu just closed) and React runs that one first. A layout
            // effect: the focus is on the row when the commit ends, so a key pressed right after
            // (Enter after ArrowDown) reaches that row and not the one before
            React.useLayoutEffect(() => {
                const want = wantFocus.current;
                if (want == null || !bodyRef.current) return;
                const tr = bodyRef.current.querySelector(`tr[data-row-index="${want}"]`);
                if (tr) {
                    tr.focus({ preventScroll: true });
                    wantFocus.current = null;
                }
            });

            const cycleSort = (key) => setSort(s => (!s || s.key !== key) ? { key, dir: 'asc' }
                : s.dir === 'asc' ? { key, dir: 'desc' } : null);

            const setWidth = (key, w) => setPrefs(p => ({ ...p, w: { ...(p.w || {}), [key]: w } }));
            const commitWidth = (key, w) => keep({ ...prefsRef.current, w: { ...(prefsRef.current.w || {}), [key]: w } });
            const startResize = (e, c) => {
                if (e.button !== 0) return;
                e.preventDefault();
                e.stopPropagation();
                const grip = e.currentTarget;
                const th = grip.parentElement;
                const x0 = e.clientX;
                const w0 = Math.round(th.getBoundingClientRect().width);
                const min = c.min || 48;
                let w = w0;
                try { grip.setPointerCapture(e.pointerId); } catch (_) {}
                document.body.classList.add('cr-col-resizing');
                const move = (ev) => { w = Math.max(min, Math.round(w0 + ev.clientX - x0)); setWidth(c.key, w); };
                const up = () => {
                    grip.removeEventListener('pointermove', move);
                    grip.removeEventListener('pointerup', up);
                    grip.removeEventListener('pointercancel', up);
                    document.body.classList.remove('cr-col-resizing');
                    commitWidth(c.key, w);
                };
                grip.addEventListener('pointermove', move);
                grip.addEventListener('pointerup', up);
                grip.addEventListener('pointercancel', up);
            };
            const keyResize = (e, c) => {
                if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
                e.preventDefault();
                const th = e.currentTarget.parentElement;
                const w = Math.max(c.min || 48, Math.round(th.getBoundingClientRect().width) + (e.key === 'ArrowRight' ? 16 : -16));
                commitWidth(c.key, w);
            };
            const resetWidth = (c) => {
                const w = { ...(prefsRef.current.w || {}) };
                delete w[c.key];
                const next = { ...prefsRef.current, w };
                if (!Object.keys(w).length) delete next.w;
                keep(next);
            };
            const toggleCol = (c) => {
                const h = { ...(prefsRef.current.h || {}), [c.key]: !isHidden(c) };
                keep({ ...prefsRef.current, h });
            };

            const moveTo = (idx) => {
                if (!shown.length) return;
                const i = crClamp(idx, 0, shown.length - 1);
                setFocusIdx(i);
                wantFocus.current = i;
                const el = scrollRef.current;
                if (!el) return;
                const headH = headRef.current ? headRef.current.offsetHeight : 0;
                const top = i * rowHeight;
                if (top < el.scrollTop) el.scrollTop = top;
                else if (top + rowHeight + headH > el.scrollTop + el.clientHeight) el.scrollTop = top + rowHeight + headH - el.clientHeight;
                if (virtual) measure();
            };
            const pageRows = Math.max(1, Math.floor(viewH / rowHeight) - 1);
            const onRowKey = (e, r, idx) => {
                if (e.key === 'ArrowDown') { e.preventDefault(); moveTo(idx + 1); }
                else if (e.key === 'ArrowUp') { e.preventDefault(); moveTo(idx - 1); }
                else if (e.key === 'Home') { e.preventDefault(); moveTo(0); }
                else if (e.key === 'End') { e.preventDefault(); moveTo(shown.length - 1); }
                else if (e.key === 'PageDown') { e.preventDefault(); moveTo(idx + pageRows); }
                else if (e.key === 'PageUp') { e.preventDefault(); moveTo(idx - pageRows); }
                else if (e.key === 'Enter' && onRowClick) { e.preventDefault(); onRowClick(r); }
                else if (onRowContextMenu && (e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10'))) {
                    e.preventDefault();
                    const box = e.currentTarget.getBoundingClientRect();
                    onRowContextMenu(r, { clientX: box.left + 24, clientY: box.bottom, preventDefault() {} });
                }
            };

            const keyOf = (r, i) => (rowKey ? rowKey(r) : (r && (r.id ?? r.key))) ?? i;
            const colSpan = Math.max(1, visible.length);
            const minWidth = visible.reduce((sum, c) => sum + (widthOf(c) || c.min || 120), 0);

            let state = null;
            if (error) {
                state = <td colSpan={colSpan} className="cr-state cr-state-error" role="alert">{typeof error === 'string' ? error : t('crLoadFailed')}</td>;
            } else if (loading && !shown.length) {
                state = <td colSpan={colSpan} className="cr-state"><span className="cr-spinner" aria-hidden="true" />{t('loading')}</td>;
            } else if (!shown.length) {
                state = <td colSpan={colSpan} className="cr-state">{all.length ? t('crNoMatch') : (emptyText || t('crNothingToShow'))}</td>;
            }

            const showTools = toolbar || actions || searchable || columnMenu;
            return (
                <div className="cr-table-wrap" data-cr-table={id || ''}>
                    {showTools && (
                        <div className="cr-table-toolbar">
                            <div className="cr-table-toolbar-left">{toolbar}</div>
                            <div className="cr-table-toolbar-right">
                                {loading && shown.length > 0 && <span className="cr-spinner" role="status" aria-label={t('loading')} />}
                                {searchable && (
                                    <div className="cr-search-box">
                                        <Icons.Search className="cr-search-ico" />
                                        <input type="search" className="cr-input" value={query}
                                            onChange={e => setQuery(e.target.value)}
                                            placeholder={searchPlaceholder || t('crSearchTable')}
                                            aria-label={searchPlaceholder || t('crSearchTable')} />
                                    </div>
                                )}
                                {showCount && (
                                    <span className="cr-table-count" aria-live="polite">
                                        {t('crRowsShown').replace('{shown}', shown.length).replace('{total}', all.length)}
                                    </span>
                                )}
                                {actions}
                                {columnMenu && (
                                    <div className="cr-menu-anchor">
                                        <button type="button" className="cr-icon-btn" aria-haspopup="true" aria-expanded={menuOpen}
                                            title={t('listColumns')} aria-label={t('listColumns')} data-cr-colmenu=""
                                            onClick={() => setMenuOpen(o => !o)}>
                                            <span className="cr-ico" aria-hidden="true"><Icons.Eye /></span>
                                        </button>
                                        {menuOpen && (
                                            <>
                                                <div className="cr-click-away" onClick={() => setMenuOpen(false)} />
                                                <div className="cr-menu" role="group" aria-label={t('listColumns')}
                                                    onKeyDown={e => { if (e.key === 'Escape') setMenuOpen(false); }}>
                                                    {columns.map(c => {
                                                        const label = c.menuLabel || c.label;
                                                        if (!label) return null;
                                                        const on = !isHidden(c);
                                                        return (
                                                            <label key={c.key} className="cr-menu-item cr-menu-check">
                                                                <input type="checkbox" checked={on} data-cr-col={c.key}
                                                                    disabled={on && visible.length === 1}
                                                                    onChange={() => toggleCol(c)} />
                                                                <span>{label}</span>
                                                            </label>
                                                        );
                                                    })}
                                                    <div className="cr-menu-sep" />
                                                    <button type="button" className="cr-menu-item" data-cr-reset=""
                                                        onClick={() => { keep({}); setMenuOpen(false); }}>
                                                        {t('crResetColumns')}
                                                    </button>
                                                </div>
                                            </>
                                        )}
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                    <div className="cr-table-scroll" ref={scrollRef} style={maxHeight ? { maxHeight } : undefined}
                        onScroll={virtual ? measure : undefined}>
                        <table className="corp-datagrid cr-table" role="grid" aria-label={ariaLabel}
                            aria-rowcount={shown.length + 1} aria-busy={loading || undefined} style={{ minWidth }}>
                            <colgroup>
                                {visible.map(c => {
                                    const w = widthOf(c);
                                    return <col key={c.key} style={w ? { width: w } : undefined} />;
                                })}
                            </colgroup>
                            <thead ref={headRef}>
                                <tr role="row">
                                    {visible.map(c => {
                                        const sortable = c.sortable !== false;
                                        const dir = sort && sort.key === c.key ? sort.dir : null;
                                        const label = c.menuLabel || c.label;
                                        return (
                                            <th key={c.key} scope="col" data-cr-col={c.key}
                                                className={`cr-th${c.align === 'right' ? ' cr-right' : ''}`}
                                                aria-sort={dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : (sortable ? 'none' : undefined)}>
                                                {sortable ? (
                                                    <button type="button" className="cr-th-btn" onClick={() => cycleSort(c.key)}
                                                        title={c.title || label} aria-label={c.label ? undefined : label}>
                                                        <span className="cr-th-text">{c.label}</span>
                                                        <span className={`cr-sort${dir ? ' cr-sort-' + dir : ''}`} aria-hidden="true" />
                                                    </button>
                                                ) : <span className="cr-th-text" title={c.title}>{c.label}</span>}
                                                {c.resizable !== false && (
                                                    <span className="cr-col-grip" role="separator" aria-orientation="vertical" tabIndex={0}
                                                        aria-label={t('crResizeColumn').replace('{col}', label || c.key)}
                                                        onPointerDown={e => startResize(e, c)} onKeyDown={e => keyResize(e, c)}
                                                        onDoubleClick={() => resetWidth(c)} onClick={e => e.stopPropagation()} />
                                                )}
                                            </th>
                                        );
                                    })}
                                </tr>
                            </thead>
                            <tbody ref={bodyRef}>
                                {state && <tr className="cr-state-row">{state}</tr>}
                                {virtual && start > 0 && (
                                    <tr className="cr-spacer" aria-hidden="true" style={{ height: start * rowHeight }}><td colSpan={colSpan} /></tr>
                                )}
                                {shown.slice(start, end).map((r, n) => {
                                    const idx = start + n;
                                    const k = keyOf(r, idx);
                                    const sel = selectedKey != null && k === selectedKey;
                                    const row = (
                                        <tr key={k} data-row-index={idx} aria-rowindex={idx + 2} aria-selected={sel}
                                            tabIndex={idx === fi ? 0 : -1} style={{ height: rowHeight }}
                                            className={`cr-row${onRowClick ? ' cr-row-click' : ''}${sel ? ' corp-row-selected' : ''}${rowClassName ? ' ' + (rowClassName(r) || '') : ''}`}
                                            onClick={() => { setFocusIdx(idx); if (onRowClick) onRowClick(r); }}
                                            onContextMenu={onRowContextMenu ? (e) => { e.preventDefault(); setFocusIdx(idx); onRowContextMenu(r, e); } : undefined}
                                            onKeyDown={e => onRowKey(e, r, idx)}>
                                            {visible.map(c => (
                                                <td key={c.key} className={`${c.align === 'right' ? 'cr-right' : ''}${c.mono ? ' cr-mono' : ''}`}>
                                                    {c.render ? c.render(r) : (r[c.key] ?? '')}
                                                </td>
                                            ))}
                                        </tr>
                                    );
                                    if (!opened(k)) return row;
                                    return (
                                        <React.Fragment key={k}>
                                            {row}
                                            <tr className="cr-row-detail" data-cr-row-detail={k}>
                                                <td colSpan={colSpan}>{renderExpanded(r)}</td>
                                            </tr>
                                        </React.Fragment>
                                    );
                                })}
                                {virtual && end < shown.length && (
                                    <tr className="cr-spacer" aria-hidden="true" style={{ height: (shown.length - end) * rowHeight }}><td colSpan={colSpan} /></tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            );
        }

        // --- header -------------------------------------------------------------

        function CrBreadcrumbs({ crumbs }) {
            const { t } = useTranslation();
            if (!crumbs || !crumbs.length) return null;
            return (
                <nav className="cr-crumbs" aria-label={t('crBreadcrumbs')}>
                    <ol>
                        {crumbs.map((c, i) => {
                            const last = i === crumbs.length - 1;
                            const body = <>{c.icon && <span className="cr-ico" aria-hidden="true">{c.icon}</span>}<span className="cr-crumb-text">{c.label}</span></>;
                            return (
                                <li key={c.key} data-cr-crumb={c.key}>
                                    {i > 0 && <span className="cr-crumb-sep" aria-hidden="true">/</span>}
                                    {c.onClick && !last
                                        ? <button type="button" className="cr-crumb" onClick={c.onClick}>{body}</button>
                                        : <span className={`cr-crumb${last ? ' cr-crumb-current' : ''}`} aria-current={last ? 'page' : undefined}>{body}</span>}
                                </li>
                            );
                        })}
                    </ol>
                </nav>
            );
        }

        // The compact header of the redesign. The search, the theme switch, the settings and
        // task buttons and the user menu are the very elements the classic header renders
        // (built once in the dashboard), only laid out differently here. Like classic Corporate
        // it has no language switcher (that lives in My Profile) and no cluster picker, the
        // tree and the breadcrumbs already do that job.
        function CrHeader({ drawerToggle, logo, search, themeToggle, settings, taskToggle, userMenu, crumbs, onOpenPalette }) {
            const { t } = useTranslation();
            const mac = typeof navigator !== 'undefined' && (navigator.platform || '').includes('Mac');
            const ref = useRef(null);
            // the classic header buttons carry a title only; here they get a name that follows it
            useEffect(() => {
                const root = ref.current;
                if (!root) return;
                root.querySelectorAll('.cr-header-tools button').forEach(b => {
                    const text = b.textContent.trim();
                    // an icon, maybe with a count badge: the title says what it is
                    if (!b.title || (text && !/^\d+$/.test(text)) || (b.getAttribute('aria-label') && !b.hasAttribute('data-cr-named'))) return;
                    const name = text ? `${b.title} (${text})` : b.title;
                    if (b.getAttribute('aria-label') !== name) b.setAttribute('aria-label', name);
                    b.setAttribute('data-cr-named', '');
                });
                const menu = root.querySelector('[data-user-menu]');
                if (menu) {
                    menu.setAttribute('aria-label', t('crUserMenu'));
                    menu.setAttribute('aria-haspopup', 'menu');
                    menu.setAttribute('aria-expanded', menu.nextElementSibling ? 'true' : 'false');
                }
            });
            const skip = (e) => {
                const main = document.getElementById('cr-main');
                if (!main) return;
                e.preventDefault();
                main.focus({ preventScroll: false });
            };
            return (
                <header className="cr-header pp-header-row" data-cr-header="" ref={ref}>
                    <a className="cr-skip" href="#cr-main" onClick={skip} data-cr-skip="">{t('crSkipToContent')}</a>
                    <div className="cr-header-left">
                        {drawerToggle}
                        <div className="cr-brand">{logo}</div>
                        <CrBreadcrumbs crumbs={crumbs} />
                    </div>
                    <div className="cr-header-right pp-header-actions">
                        <div className="cr-header-search">{search}</div>
                        <button type="button" className="cr-kbd-hint" onClick={onOpenPalette} data-cr-palette=""
                            title={t('crCommandPalette')} aria-label={`${t('crCommandPalette')} (${mac ? 'Cmd' : 'Ctrl'}+K)`}
                            aria-keyshortcuts={mac ? 'Meta+K' : 'Control+K'}>
                            <kbd>{mac ? '⌘' : 'Ctrl'}</kbd><kbd>K</kbd>
                        </button>
                        <span className="cr-header-divider" aria-hidden="true" />
                        <div className="cr-header-tools">
                            {themeToggle}
                            {settings}
                            {taskToggle}
                        </div>
                        {userMenu}
                    </div>
                </header>
            );
        }

        // --- sidebar ------------------------------------------------------------

        // The tree keys on a row of the inventory tree: Right opens a cluster or steps into it,
        // Left closes it or steps out to the cluster, Up/Down/Home/End walk the rows on screen.
        // Up and Down of a child row stay with the classic handler of the row.
        function crTreeKey(e, expanded, toggle) {
            const row = e.currentTarget;
            const tree = row.closest('[role="tree"]');
            if (!tree) return;
            const rows = Array.from(tree.querySelectorAll('[role="treeitem"]'));
            const at = rows.indexOf(row);
            const go = (i) => { if (rows[i]) { e.preventDefault(); rows[i].focus(); } };
            if (e.key === 'ArrowDown') go(at + 1);
            else if (e.key === 'ArrowUp') go(at - 1);
            else if (e.key === 'Home') go(0);
            else if (e.key === 'End') go(rows.length - 1);
            else if (e.key === 'ArrowRight' && expanded === false && toggle) { e.preventDefault(); toggle(); }
            else if (e.key === 'ArrowRight' && expanded) go(at + 1);
            else if (e.key === 'ArrowLeft' && expanded && toggle) { e.preventDefault(); toggle(); }
            else if (e.key === 'ArrowLeft' && expanded === undefined) {
                const group = row.closest('[role="group"]');
                const parent = group && group.previousElementSibling;
                if (parent && parent.getAttribute('role') === 'treeitem') { e.preventDefault(); parent.focus(); }
            }
        }

        // Drag handle between the sidebar and the content. While dragging only the sidebar's own
        // width changes in the DOM; the dashboard state follows once on release, so a sidebar
        // with thousands of rows does not re-render on every pointer move. With a big tree even
        // the relayout of a width change is too slow to follow the pointer (measured ~180 ms per
        // move at 10k guests), so then a guide line moves and the width lands on release.
        function CrSidebarHandle({ width, collapsed, onCommit, onToggle }) {
            const { t } = useTranslation();
            const sidebar = (grip) => grip.parentElement && grip.parentElement.querySelector('.pp-sidebar.cr-sidebar');
            const start = (e) => {
                if (collapsed || e.button !== 0) return;
                e.preventDefault();
                const grip = e.currentTarget;
                const side = sidebar(grip);
                const x0 = e.clientX;
                const left = side ? side.getBoundingClientRect().left : 0;
                let w = width;
                let guide = null;
                if (side && side.getElementsByClassName('corp-tree-child').length > CR_SIDEBAR.liveRows) {
                    guide = document.createElement('div');
                    guide.className = 'cr-side-guide';
                    guide.style.left = (left + width) + 'px';
                    document.body.appendChild(guide);
                }
                try { grip.setPointerCapture(e.pointerId); } catch (_) {}
                document.body.classList.add('cr-col-resizing');
                const move = (ev) => {
                    w = crClamp(Math.round(width + ev.clientX - x0), CR_SIDEBAR.min, CR_SIDEBAR.max);
                    if (guide) guide.style.left = (left + w) + 'px';
                    else if (side) side.style.width = w + 'px';
                };
                const up = () => {
                    grip.removeEventListener('pointermove', move);
                    grip.removeEventListener('pointerup', up);
                    grip.removeEventListener('pointercancel', up);
                    document.body.classList.remove('cr-col-resizing');
                    if (guide) guide.remove();
                    onCommit(w);
                };
                grip.addEventListener('pointermove', move);
                grip.addEventListener('pointerup', up);
                grip.addEventListener('pointercancel', up);
            };
            const onKey = (e) => {
                if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
                    e.preventDefault();
                    if (!collapsed) onCommit(crClamp(width + (e.key === 'ArrowRight' ? 16 : -16), CR_SIDEBAR.min, CR_SIDEBAR.max));
                } else if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onToggle();
                } else if (e.key === 'Home') {
                    e.preventDefault();
                    onCommit(CR_SIDEBAR.def);
                }
            };
            return (
                <div className={`cr-side-handle${collapsed ? ' cr-side-handle-off' : ''}`} role="separator"
                    aria-orientation="vertical" aria-valuenow={collapsed ? CR_SIDEBAR.rail : width}
                    aria-valuemin={CR_SIDEBAR.min} aria-valuemax={CR_SIDEBAR.max} tabIndex={0}
                    aria-label={t('crResizeSidebar')} title={t('crResizeSidebar')} data-cr-side-handle=""
                    onPointerDown={start} onKeyDown={onKey} onDoubleClick={() => !collapsed && onCommit(CR_SIDEBAR.def)} />
            );
        }

        // the folded sidebar: a rail with the view switcher, a way back and the filter.
        // LW Nov 2026 - and the global views of the Tools section ({id, icon, label, active, onClick}),
        // which open from here without unfolding the sidebar
        function CrSidebarRail({ views, active, onView, onExpand, tools }) {
            const { t } = useTranslation();
            const focusFilter = () => {
                onExpand();
                setTimeout(() => {
                    const input = document.querySelector('.pp-sidebar.cr-sidebar .corp-sidebar-search');
                    if (input) input.focus();
                }, 0);
            };
            return (
                <div className="cr-rail" role="toolbar" aria-orientation="vertical" aria-label={t('crInventory')}>
                    <button type="button" className="cr-rail-btn" onClick={onExpand} data-cr-expand=""
                        aria-label={t('crExpandSidebar')} title={t('crExpandSidebar')}>
                        <Icons.ChevronRight className="w-4 h-4" />
                    </button>
                    <span className="cr-rail-sep" aria-hidden="true" />
                    {views.map(v => (
                        <button key={v.id} type="button" className={`cr-rail-btn${active === v.id ? ' active' : ''}`}
                            aria-pressed={active === v.id} aria-label={v.label} title={v.label}
                            onClick={() => { onView(v.id); onExpand(); }}>
                            <v.icon className="w-4 h-4" />
                        </button>
                    ))}
                    <button type="button" className="cr-rail-btn" onClick={focusFilter}
                        aria-label={t('filterSidebar')} title={t('filterSidebar')}>
                        <Icons.Search className="w-4 h-4" />
                    </button>
                    {tools && tools.length > 0 && (
                        <>
                            <span className="cr-rail-sep" aria-hidden="true" />
                            {tools.map(tool => (
                                <button key={tool.id} type="button" className={`cr-rail-btn${tool.active ? ' active' : ''}`}
                                    aria-pressed={!!tool.active} aria-label={tool.label} title={tool.label} data-cr-rail-tool={tool.id}
                                    onClick={tool.onClick}>
                                    <tool.icon className="w-4 h-4" />
                                </button>
                            ))}
                        </>
                    )}
                </div>
            );
        }
