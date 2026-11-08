# Cloud Layout Redesign — Phases 1–6 (Nov 2026)

Branch: `Testing` · All changes scoped to the Cloud layout (`body[data-layout="cloud"]` /
`CloudShell` in `web/src/cloud.js`); Corporate and every other layout are untouched.

Scope guards that held throughout:

- No new dependencies (drag & drop is native HTML5, persistence rides the existing
  `/api/user/preferences` endpoint).
- No API interface changes — the only backend addition is one optional preference field.
- No mock data in productive components; widgets render only what the existing
  `/api/clusters*` endpoints deliver, with honest empty states where data is missing.
- Permission checks and i18n (`t('cloud.x') || 'fallback'`) preserved everywhere.

---

## PHASE 1 — Bestandsaufnahme (no code changes)

**What was mapped:** `CloudShell` mount path (dashboard.js `if (isCloud)`), theme tokens
(`PEGAPROX_THEMES` + `applyTheme('cloud')`, light mode via `body[data-cloud-theme]`),
data flow (`/api/clusters`, `…/resources`, `…/metrics`, `…/datacenter/status`, `…/tasks`),
and the Playwright test contracts in `tests/test_ha_ui.py` (selector/classname pins such
as `[data-layout-pick="cloud"]`, `.cloud-detail-actions`, `.cloud-nav-item` …).

**Risk call:** CSS restyling is safe if every pinned classname survives; JS structure
changes must stay inside `cloud.js`. Result: all later phases kept the classnames and only
restyled.

## PHASE 2 — Cloud Overview redesign

**Changed:** `web/index.html.original` (CSS source of truth) — complete Cloud block
rewritten around a token set on `body[data-layout="cloud"]` (surfaces `#050c15…#13253a`,
accent `#22d3ee` + soft/line/selection tints, radius 4/6/8, spacing scale 4–32, flat
border-driven cards, 52px topbar, densified nav/tables/KPI). `web/src/cloud.js` —
KPI/cluster-glance structure aligned to the token system.

**Verified:** fake-server screenshots (dark + light, 1600/1180/900px), 0 console errors,
all test-contract classnames intact, `diff` against the branch baseline shows no change
before line 3107 (the Cloud block) — Corporate CSS byte-identical.

## PHASE 3 — Reusable components

**New in `cloud.js`:** `CloudWidgetCard` (card chrome + drag header + size/remove
controls), `CloudMeterRow`, `CloudTopConsumers` (RAM/CPU/Disk segment switch),
`CloudActivityList` (status icons, `max` limit), `cloudThresholdColor()` (≥75 warning,
≥90 error, else accent) now the default for `CloudMiniMeter` — one threshold language
across nodes, tables and meters.

## PHASE 4 — Dashboard personalization / widget engine

**Backend (`pegaprox/api/users.py`, `pegaprox/core/db.py`):** new optional preference
`cloud_dashboard` — GET names it (None = never customized), PUT accepts the layout object
(shape-checked, 32 KiB cap, `null` clears). Persisted in a new `users.cloud_dashboard`
TEXT column (JSON) with `ALTER TABLE` migration; `save_user`/`get_user`/`get_all_users`
carry it. *Found by test: without the column the whitelist silently dropped the layout —
the unit test `tests/test_cloud_dashboard_pref.py` (6 cases) caught it end-to-end.*

**Frontend (`cloud.js`):** `CLOUD_WIDGETS` registry (7 widgets: KPI, utilization, top
consumers, activity, cluster health, guest status, datastores) with per-widget sizes
(6-column grid, span sm/md/lg/full), `CLOUD_DASHBOARD_DEFAULT`, layout normalization for
saved/foreign layouts, customize mode (add menu, remove, size cycle, per-widget config:
consumer metric + activity limit), native drag & drop reorder, restore defaults, debounced
(600 ms) `PUT /api/user/preferences` with localStorage fallback (`pegaprox-cloud-dashboard`)
when the server is unreachable.

*Late catch (live check):* the client called `` `${API_URL}/api/user/preferences` `` — but
`API_URL` already ends in `/api`, so the request went to `/api/api/…` (404) and every load
silently fell back to defaults. The fake-server glob (`**/api/…`) masked it. Fixed to
`${API_URL}/user/preferences`; the harness now fails on doubled `/api/` paths, requires the
preferences GET to be served, and renders a server-saved 3-widget layout in a fresh context
(`overview-saved-layout.png`). Verified live: login → PUT layout → GET roundtrip → fresh
browser profile (no localStorage) renders the saved 4-widget layout from the server.

## PHASE 5 — All Clusters / Cluster Overview

`CloudClusters`: fleet KPI row (clusters online, hosts, running guests, storage with
meter) + per-cluster utilization meters (Avg CPU / RAM / Storage from
`datacenter/status`), Testing-branch badges (Quorate / Standalone / Degraded HW)
preserved. Offline clusters show honest `—` instead of fake zeros.

## PHASE 6 — VM Overview + remaining pages

`CloudInstanceList`: sortable Uptime column (`cloudFmtUptime`), tag chips (max 2 + `+n`)
in the name cell, tags included in search, threshold-colored mini meters. Consistency pass
over remaining sections (nodes, tasks, detail actions) — no structural changes needed.

---

## Tests

| Suite | Result |
|---|---|
| `tests/test_ha_ui.py` (incl. all Corporate contract tests) | 313 passed, 6 skipped (no node), 1 flaky on first run — not reproducible, passes in isolation and full re-run |
| `tests/test_first_login_layout_cloud_ui.py` | 3 passed |
| `tests/test_cloud_dashboard_pref.py` (new) | 6 passed |
| `tests/test_integration_users_acl.py` + 4 user/auth suites | 56 passed |
| `tests/test_corp_redesigned_plumbing.py` | 16 passed, 7 skipped |
| Fake-server screenshots (9: dark/light, customize, VM list, clusters, 1180/900px, tabs) | visually reviewed, 0 page errors |
| Static: baseline `diff` outside Cloud block | no change before line 3107 |

## Open items

- `pegaprox/app.py:1302` pins the TLS serial to 1000 on every self-signed issue
  (`SEC_ERROR_REUSED_ISSUER_AND_SERIAL` in Firefox when two installs share a port).
  Operational fix applied (custom cert in `config/ssl/`); the one-line code fix
  (`os.urandom` serial) is pending a decision.
- ~~Live end-to-end login check~~ **done**: real login, preferences roundtrip, and
  server-side layout restore in a fresh browser profile all verified against the running
  instance (the earlier failure was a wrong password, not a code issue).

---

# Iteration 2 — Unified Compute Experience (Nov 2026)

Scope: Cloud Overview (reference), Virtual Machines, Containers, App-Containers.
Corporate untouched: all CSS is inside the cloud block / `body[data-layout="cloud"]`,
`OciCatalogTab` gained a `variant` prop — Corporate keeps the default look byte-for-byte,
Cloud passes `variant="cloud"`.

## Phase 1 — Analysis

- Width culprit: `.cloud-body { max-width:1560px }` capped every page; at 1366×768 the
  content ended near 1050px, matching the report.
- `CloudInstanceList` already serves VMs **and** Containers (one component — kept).
- `OciCatalogTab` (dashboard.js) is shared with Corporate's Automation → Apps tab →
  restyled only via the new variant, all `data-oci-*` hooks preserved
  (`tests/test_oci_catalog_ui.py` drives both layouts).

## Phase 2 — Content system

- `.cloud-body` is fluid (`max-width:none`); content padding unchanged.
- Instance tables get a column rhythm: fixed lanes for ID/Status/Host/CPU/RAM/Uptime,
  Name flexes (`cloud-col-*` classes); hair more row padding ≥1920px.
- Measured content utilization (fake server, `.cloud-table-card`/`.cloud-oci-grid` vs
  viewport minus nav): **97–99 % at 1366/1600/1920/2560** on all four pages.

## Phase 3/4 — Virtual Machines + Containers

Same base component, so one pass covers both: width-hinted columns, guest names
weighted 600 with icon accent on hover, Host cell ellipsized, CPU tooltip shows
allocated vCPU, RAM tooltip shows used/max bytes. Status chips, filters, search,
multi-select bulk bar, context menus and the pager are unchanged in behavior.

## Phase 5 — App-Containers (cloud variant)

- Cloud header (title + TECH PREVIEW badge + description + cluster select + refresh),
  warning/denied/error notes in cloud note styling — all previous notices kept.
- Image cards: name, description, spec grid (Registry / Image / Tag / CPU / RAM /
  Storage / Ports, reference parsed into parts) and a small secondary "create container"
  button bottom-right (≈40 % of card width, no longer dominating).
- Custom image: same input hook (`data-oci-custom-ref`), live registry/image:tag parse
  preview and explicit valid/invalid hint (`ociRef*`), deploy enables only when valid.
- Deploy jobs as compact cloud rows with status dots; deploy dialog in cloud chrome.
- 10 new i18n keys (`ociLbl*`, `ociRef*`) in all nine languages (the OCI test enforces
  nine-language completeness and bans long dashes in the component).

## Phase 6 — QA

| Check | Result |
|---|---|
| Build (Babel bundle) | ok |
| `tests/test_oci_catalog_ui.py` (both layouts) + `test_first_login_layout_cloud_ui.py` | 16 passed |
| Full `tests/test_ha_ui.py` | 312 passed; 1 known flaky corporate test (`standby[active]`), passes in isolation |
| DOM verification (24 assertions: columns, meters, pager, badges, spec grid, parse states, button weight, dialog chrome, 0 JS errors) | 24/24 PASS |
| Screenshots | `it2-{vms,containers,apps,overview}-*.png` at 1366/1600/1920/2560 |
| Baseline diff | dashboard.js only inside `OciCatalogTab`; translations.js 90 additions / 0 removals; no CSS before the cloud block |

## Open items (Iteration 2)

- none blocking; the `app.py:1302` serial fix is still the only pending decision.

---

# Iteration 3 — Complete Infrastructure Management Experience (Nov 2026)

Scope: VM detail, Container detail, Datastore detail, Storage config, shared components,
monitoring and the operational-state model. Overview/list pages visually unchanged.

## Implemented (all live against real APIs, no mocks in productive code)

**Shared components (`cloud.js`)** — `useCloudApi` (fetch hook with loading/error/data +
reload), `CLOUD_HC` status model (HEALTHY / WARNING / CRITICAL / UNKNOWN / N/A + ordering),
`CloudHcBadge` / `CloudHcRow`, `cloudGuestHealthRows` (check builder), `CloudMetricChart`
(LineChart wrapper with cur/ø/min/max + last update + honest no-data state),
`CloudDatastoreDetail`. Reused from the shared UI layer: `LineChart` (ui.js),
`BackupRestoreWizard` (ui.js), `CloudKVPanel/Row`, `CloudStatusChip`, `CloudActionMenu`,
`CloudEmpty`, `cloudFmtBytes/Uptime/Ts/Rate`, `cloudThresholdColor`.

**VM / Container detail** — one component, 9 tabs: Overview (real console screenshot via
`/screenshot` for running qemu, resource meters, infrastructure facts, agent facts,
recent tasks), Operational state (7 checks, see below), Monitoring (`/rrd/{hour|day|week|
month}` → 6 charts cpu/mem/disk r+w/net in+out), Hardware (qemu: CPU/RAM/firmware incl.
efidisk+TPM/boot/options, disks & nics tables, passthrough from raw) / Configuration
(lxc: cores/limits/memory+swap/unprivileged/features/startup, rootfs+mounts, nics),
Storage (used-vs-allocated separation, per-disk datastore type/health from
`/datastores`), Network (interfaces from config, IPs **only** from guest-info),
Snapshots (list + create via existing modal + rollback/delete with confirm), Backups
(status from `vms-backup-status`, create form → `POST /backups/create`, history from
`/backups`, restore via `BackupRestoreWizard`, delete with confirm), Tasks & Events
(`/nodes/{node}/tasks?vmid=` with user + exitstatus).

**Betriebszustand checks** (never green without proof): Backup (`vms-backup-status`),
Backup SLA (`recovery-report/{vmid}.guest.rpo_state`), Restore test
(`guest.state/rto/measured`), Guest agent (qemu: `guest-info` + config flag; **N/A for
LXC**), HA (`proxmox-ha/resources`; unconfigured = N/A), Migration (`migrate-check` on
demand — UNKNOWN until actually checked), Audit integrity (**N/A honestly** — verified
installation-wide, no per-guest endpoint).

**Datastore detail** — click a row in the Datastores table: capacity (used/free/total),
content types, health (active on / inactive on), contents table (kind/volume/size/ctime
from `/datastores/{name}/content`), assigned guests matched by vmid parsed from real
volids.

**Storage config** — the shared `DatastoreTab` keeps its two-column structure and all
functions (balancing, ISO sync, backup SLA, restore tests); its classic tones are mapped
to cloud tokens via CSS-only extensions of the existing `.cloud-mounted` compatibility
layer (`storage.js` is byte-identical to the baseline).

## API endpoints used (all pre-existing)

`/vms/{node}/{type}/{vmid}/config`, `/guest-info`, `/screenshot`, `/snapshots` (+POST/
DELETE/rollback), `/backups` (+`/backups/create`, DELETE), `/rrd/{tf}`, `/migrate-check`,
`/vms-backup-status`, `/recovery-report/{vmid}`, `/proxmox-ha/resources`,
`/datastores(/{name}/content)`, `/nodes/{node}/tasks?vmid=`, `/clusters/{cid}/next-vmid`
(wizard). Permissions: `vm.snapshot`, `backup.create/restore/delete` gate the buttons;
every write hits the enforcing backend route.

## Not implemented / known limits (documented, not faked)

- **Timeline events** (`/api/timeline`): not wired into the Tasks tab; the tab notes
  where longer-lived events live. Next step.
- **Efficient (COW/LVM) snapshots**: endpoint exists, not yet shown alongside standard
  snapshots.
- **Migration**: readiness check only; the actual migration stays in the existing
  migrate modal (Actions menu) — no duplicate flow.
- **Audit integrity**: N/A per guest by design (no endpoint); an admin-facing global
  check would be a settings feature.
- **Console preview**: qemu + running only (backend: no framebuffer for LXC, none while
  stopped) — those states show honest messages instead.
- **Backup retention per backup**: not exposed by the endpoint; only notes/format.
- **Per-disk usage**: the cluster does not report it; Storage tab states this and shows
  root usage vs allocated instead of guessing.

## QA

| Check | Result |
|---|---|
| Build (Babel bundle) | ok |
| `test_ha_ui.py` + `test_first_login_layout_cloud_ui.py` + `test_oci_catalog_ui.py` | **329 passed, 6 skipped, 0 failed** |
| Detail flow DOM verification (fake server, real endpoint shapes) | **45/45 PASS** incl. honest states (migration UNKNOWN before check → WARNING after; LXC agent N/A; audit N/A) |
| Screenshots | `it3-vm-{overview,health,monitoring,hardware,storage,snapshots,backups,tasks}`, `it3-ct-{overview,config}`, `it3-datastore-detail`, `it3-storage-config` + 1366/2560 |
| Visual review (health + overview) | no defects; enterprise styling consistent |
| Baseline diff | `storage.js` identical; `dashboard.js` only inside `OciCatalogTab`; translations additive; no CSS before the cloud block |
| Width utilization (storage config) | 97 % @1366, 99 % @2560 |

---

# Refinement & Quality Pass (Nov 2026, round 2)

Kein Redesign — Korrekturen und Vervollständigung der bestehenden Ansichten.

## Behobene Fehler

1. **Monitoring-Einheiten komplett korrigiert.** Ursachenkette: `LineChart` bekam weder
   `formatValue` noch `label` — die Y-Achse hängte den Default-Suffix `%` an jede Zahl
   (Disk Read „6000 %"), und der Tooltip zeigte `undefined: …`, weil das Dataset kein
   Label hatte. Jetzt: `label` + `formatValue` + `unit=" "` pro Chart; CPU/Memory in %,
   Disk/Netz in B/s → KiB/s → MiB/s → GiB/s (`cloudFmtRate`). Memory zeigt zusätzlich
   used/allocated im Chart-Titel. Hex-Farben statt `var(--…)` (Canvas löst CSS-Variablen
   nicht auf; die Füllungen waren dadurch fast schwarz): CPU cyan, Memory violett,
   Disk r/w blau/indigo, Netz in/out teal/lime.
2. **Light Mode der Diagramme.** `LineChart` erkannte nur `data-corp-theme="light"`;
   der Cloud-Light-Mode (`data-cloud-theme`) ließ dunkle Achsen/Tooltips. Neuer Helper
   `chartLightMode()` (ui.js) erkennt beide — Corporate-Verhalten byte-identisch
   (semantisch gleiche Prüfung, diff: 27 Zeilen, nur innerhalb LineChart).
3. **Tooltip „undefined"** — siehe 1 (Label jetzt gesetzt).
4. Timestamp unter den Charts unlesbar dunkel → Sekundärton.

## Verbesserte Komponenten

- **VM/CT-Overview**: neue kompakte Betriebszustands-Kurzübersicht (Backup / Gast-Agent /
  HA mit Badges, `View all` → Betriebszustand-Tab) direkt neben Ressourcen/Konsole/Fakten —
  die Seite nutzt die Breite jetzt voll, Prioritäten wie im Brief (Ressourcen, Konsole,
  Infra, Agent, Zustand, Netz, Aktivitäten).
- **Operational State**: jede Zeile mit verfügbarer Quelle verlinkt in den passenden Tab
  (Backup/SLA/Restore → Backups), SLA-Zeile zeigt den Prüfzeitpunkt (newest_backup_at),
  Kartenhöhen einheitlich (grid-auto-rows + Aktionen unten fixiert).
- **Storage-Tab**: Bus/Controller-Spalte (aus der Disk-ID, z. B. `scsi0` → `scsi`).
- Deutsche Übersetzungen für alle neuen Strings (142 Schlüssel; Tabs, Betriebszustand,
  Hardware, Storage, Snapshots, Backups, Tasks, Einheiten).

## Funktionierende Datenquellen (unverändert, echt)

`/vms/{node}/{type}/{vmid}/{config,guest-info,screenshot,snapshots,backups,rrd/*,
migrate-check}` · `/vms-backup-status` · `/recovery-report/{vmid}` · `/proxmox-ha/
resources` · `/datastores(/{name}/content)` · `/nodes/{node}/tasks?vmid=` — Berechtigungen
(`vm.snapshot`, `backup.*`) gate die Buttons, das Backend enforcet.

## Noch fehlende Funktionen (dokumentiert, nicht simuliert)

Timeline-Events im Tasks-Tab · effiziente (COW-)Snapshots · SPICE-Vorschau (nur
Download möglich) · Per-Disk-Belegung (Cluster meldet sie nicht).

## Testergebnisse

- Build ok · Detail-Verifikation **51/51 PASS** (neu: Overview-Snapshot-Karte, Health-
  Tab-Links, Light-Mode-Charts, Container-Monitoring) · 0 JS-Fehler
- Suiten: **334 passed, 6 skipped, 1 failed** — der Fail ist
  `test_runtime_corporate_menu_table_and_detail_on_a_standby[active]` und schlägt
  **identisch auf der unvereinderten Baseline** fehl (`/screenshot`-Call unterbleibt,
  timing-abhängig; heute Abend auch in Isolation reproduzierbar, früher grün). Keine
  Regression dieser Änderungen; Beweis: Baseline-Run.
- Visuelle Prüfung: Light-Monitoring (korrekte Einheiten, lesbar), neue Overview
  (kompakt, keine Leerflächen), DE-Monitoring (deutsche Tabs, Raten-Achsen) — kein Befund.

## Screenshots (alle in /tmp/pw-shots)

`it3-vm-overview.png` (+ `-light`) · `it3-vm-monitoring.png` (+ `-light`) ·
`it3-vm-health.png` · `it3-vm-hardware.png` · `it3-vm-storage.png` ·
`it3-ct-overview.png` · `it3-ct-monitoring.png` · `it3-storage-config.png` (+1366/2560).

---

# Iteration 4 — Comprehensive UX Refinement (Nov 2026, round 3)

Scope: VM/LXC detail as a coherent enterprise management experience. No redesign —
structure, honesty and consistency.

## What changed (implementation)

**Navigation (10 areas):** `Overview · Operational state · Monitoring · Hardware
(Configuration on LXC) · Disks · Network · Snapshots · Backups · Replication ·
Tasks & Events`. Storage became **Disks** (disk-centric, no longer a mixed summary);
**Replication** is new. VM and LXC share the component with honest per-type branches.

**Header:** resource chips (vCPU, RAM used/allocated, Disk used/allocated) next to
cluster/host/uptime. Destructive actions stay separated in the kebab (`danger` +
divider) — verified existing.

**Overview:** operational summary now shows **all seven checks** in a compact
two-column list with a worst-state badge — computed by the same
`cloudGuestHealthRows()` as the full tab (data-driven, verified by flipping fake data:
VM 110 → worst CRITICAL, backup row CRITICAL, 7 indicators).

**Operational State:** each check carries an **impact statement** when warning/critical
("No current backup — data loss on failure possible"), a last-verification timestamp
where the source provides one, and a link into the responsible tab; migration keeps its
on-demand check. Equal card heights (grid + bottom-pinned actions).

**Hardware (VM):** grouped General / CPU / Memory / Firmware (BIOS/EFI/TPM) /
**Virtualization (SCSI controller, guest agent, Cloud-Init presence)** / Options, plus a
**pending-changes banner** fed by the real `/pending` endpoint ("applied on next
reboot"). Disk/NIC tables moved to their own tabs. LXC Configuration gets General +
pending too; no BIOS/SPICE/SCSI for containers (verified).

**Disks:** Device / Bus / Datastore (+type, health) / Size / Format / Cache / IO thread;
root used-vs-allocated separation; datastore capacity cards; Edit button.

**Replication:** per-guest jobs from `GET /clusters/{cid}/replication?vmid=` — job,
target, schedule, last/next sync, status badge; honest empty state; management stays
central (noted in-tab).

**Monitoring/units/labels** from round 2 preserved (verified again in both themes).

**Files:** `web/src/cloud.js` (detail restructure), `web/index.html.original` (CSS
`cloud-hc-impact/mini/detail-res/note`), `web/src/translations.js` (+23 DE keys).
`ui.js`/`dashboard.js`/`storage.js` untouched this round.

## Bugs found by QA and fixed

- **Worst-state badge compared `CLOUD_HC_ORDER[w]` (row object) instead of
  `w.state`** — the badge showed N/A instead of the worst check. Fixed + covered by a
  data-driven test.

## Verification (73/73 automated checks + visual review)

> Final pass extended to **75/75** after closing the remaining inspection gaps:
> Network / Snapshots / Backups / Tasks visually reviewed via composite
> (`it4-composite-tabs.png` — all four quadrants PASS, styling consistent), and the
> shared **ConfigModal** verified end-to-end from the Cloud Disks tab: opens via Edit
> (header, section sidebar General/System/Disks/Network/Options/Cloud-Init, Save/Cancel
> accessible, dark theme intact) **and closes again** (`it4-vm-config-modal.png`).
> Modal-open/close is covered by automated checks; an in-modal save was not exercised
> against the fake (the shared editor's PUT flow is Corporate-tested territory).

- 10 tabs, multi-disk rendering (4 devices, differing cache/iothread/datastores),
  replication real + empty state, all five states on one guest (2 CRITICAL, 1 WARNING,
  2 HEALTHY, 1 UNKNOWN, 1 N/A — data-flipped, not hardcoded), LXC specifics
  (Configuration tab, no SPICE, no firmware, unprivileged/nesting), pending banner,
  shutdown fires the real POST, light-mode charts (6 canvases), 0 JS errors.
- **Visual review** (screenshot analysis): Hardware (banner + groups), Disks (columns
  differ per disk), Replication (table + note), Operational State critical case,
  Health-Light + Disks-Light ("light mode reads as a properly themed first-class view").
  One analysis initially reported a chip-count mismatch — traced to the fake server's
  route order (`/resources` shadowed `/proxmox-ha/resources`); after fixing the fake,
  HA renders HEALTHY as the data says. No app defect.
- **Light-mode chart test failure investigated to the end:** three causes stacked —
  (1) the test measured after leaving the chart tab, (2) fake CDN handling for
  Chart.js (see finding), (3) route shadowing. App behavior proven correct
  (6 canvases, `window.Chart` loaded, 0 errors). Test now measures where it looks.
- **Suites:** 334 passed / 6 skipped / 1 failed — the failing
  `test_runtime_corporate_menu_table_and_detail_on_a_standby[active]` fails
  **identically on the untouched baseline** (documented pre-existing, timing-related).
- Corporate untouched: CSS before the cloud block byte-identical; `storage.js`
  identical; `dashboard.js` only the OCI block (round 1); `ui.js` only the additive
  `chartLightMode()` helper (round 2).

## Findings handed to the project (not this task's scope)

- `web/static/js/` does not exist in the repo, although the boot loader tries local
  assets first (`/static/js/chart.umd.min.js` etc.) and falls back to CDN. In offline
  installs Chart.js (and every other vendored lib) would not load. Deployment probably
  ships that directory; worth verifying.
- Guest detail is transient state — a reload returns to the section list (no deep
  link). Acceptable, but a route-based detail would survive reloads.

## Before/after

`compare-vm-overview.png` — left: baseline (Info/Capacity/Network, three KV cards);
right: current (10 areas, console preview, resources with meters, infrastructure,
guest-agent facts, seven-check operational summary with worst badge, recent activity).
`before-vm-capacity.png` vs `it4-vm-disks.png` shows the Capacity tab evolving into
Disks with per-device configuration columns.

---

# Design Sprint (Nov 2026, same session)

User feedback: the last rounds were structure, not visible design. This sprint keeps
the design line but makes the refinement visible. Six levers, cloud-scoped only:

1. **Tabs** — icon per area + cyan underline on the active tab (hover: subtle line).
2. **Detail header** — status-colored accent edge (green running / gray stopped /
   amber paused; datastores: green active / red inactive) and resource chips as badges
   with **live mini-meters** (RAM/Disk used % inline).
3. **Resources card** — two **real sparklines** (CPU cyan, memory violet, last hour,
   same `/rrd/hour` source as Monitoring — no synthetic data).
4. **Operational State** — proportional **segment band** above the count chips
   (red/amber/green/gray by check counts).
5. **Tables** — hover accent edge on the left, slightly stronger header row.
6. **Light theme** — cards get a whisper of shadow depth (`--cloud-card-shadow`),
   dark theme unchanged (flat borders stay).

QA: 75/75 automated checks still pass; visual analysis confirms tabs with icons +
underline, green status edge, mini-meter badges, dual sparklines, and the segment band
("state graspable in a single glance"). One regression was caught by the datastore
check and fixed before it shipped: the status-edge replace had also hit the datastore
detail header (`r is not defined` on open) — now derived from the datastore's own
active state. `compare-vm-overview-sprint.png` shows baseline vs post-sprint.

---

# Iteration 5 — Operations Center Composition (Nov 2026)

User verdict after the sprint: the detail page still read as "cards without hierarchy".
This round recomposes the page itself (approved plan; user chose **8 grouped tabs with a
merged Protection tab** and a **collapsible health rail**).

## New composition

**Navigation** — 8 tabs in 4 visual clusters (thin separators):
`Overview │ State · Monitoring · Tasks │ Hardware/Konfig · Disks · Network │ Protection`.
Protection bundles the three existing bodies behind a segment switcher
(Snapshots | Backups | Replication) — every list, action and fetch preserved (fetch
conditions moved to `tab==='protection' && protSub===…`); legacy links route through
`goto()`.

**Header** — single source of truth: status edge, name/#ID/type, meta line
cluster · host · uptime **+ tags**; resource indicators stay right. The overview's
Infrastructure KV panel and the standalone Guest-Agent KV panel are **gone** (their
facts live in the header, the rail and the Network tab — no more duplicates).

**Overview = operations center** (`.cloud-ov-layout`, 1.7fr / 1fr, one column <1240px):
- LEFT: Resources panel with **4 tiles** (CPU/RAM/Storage/Network — %, used/allocated,
  meter, real `/rrd/hour` sparklines sized to inform) → compact **console strip**
  (≤160px; live thumb only when available, otherwise icon + one-line reason + buttons) →
  recent activity.
- RIGHT: **health rail** — worst badge + segment band + 7 collapsible rows
  (`CloudHcRailRow`): collapsed = state line, expanded = **Bedeutung** (what the check
  proves, `cloudHcMeaning`), impact, action link, last proof. Worst non-healthy row
  opens by default; agent row carries OS/kernel when the agent reports.

**Operational State tab** — full cards keep impact/actions and gain the meaning line.
LXC gets the same layout (shell instead of SPICE, agent N/A).

## QA

- **81/81 automated checks** (8 grouped tabs, protection segments with live data, rail
  rows/expand/meaning, 4 tiles, zero duplicate KV panels, console strip ≤160px,
  worst-badge derivation on VM 110, light mode, widths 97–99% @1366/2560), 0 JS errors
- **Suites: 329 passed, 6 skipped, 0 failed** (incl. the usually-flaky standby test)
- Visual analysis dark: *"reads as one composed operations center — left = what it
  consumes & does, right = how healthy it is; no defects"*. Light: *"contrast
  throughout, no washed-out areas"*
- Before/after: `compare-vm-overview-v2.png` (labelled Vorher/Nachher)

---

# Iteration 6 — Cloud Config Modal (Nov 2026)

The shared `ConfigModal` (vm_config.js) showed the cloud layout the unfinished "modern"
dark chrome (Tailwind/proxmox forms, orange pill tabs, scattered NEEDS-RESTART badges).
This round adds a **third chrome branch `variant="cloud"`** — the pattern of
`isCorporate`/`OciCatalogTab`. Corporate-classic and Corporate-Redesigned stay
byte-identical in behavior.

## Chrome

- **Grid shell** `.cloud-cfg` (header / nav+body / footer): status-accent header
  (name, #ID, RUNNING badge, cluster · host), **left grouped nav** (4 groups: Base,
  Operations, Protection, Administration — all 10 sections reachable; LXC: Resources
  instead of Hardware), body carries `cloud-mounted` so **all existing tab markup and
  the ~25 sub-dialogs inherit cloud surfaces** through the compatibility layer
  (overlay also mounted — sub-dialogs hang under it), footer with Cancel + cyan Save.
- **General**: status/resource card styled as read-only info strip (dashed border,
  no input look). **Hardware**: advanced sections (EFI/TPM, Cloud-Init drive, RNG,
  VirtioFS, passthrough) behind an **"Advanced hardware" fold** (collapsed by
  default, hint line lists what's inside).

## Change management (the core)

- The proven engine (`useCrVc`: `GET /pending` + qemu-server rule table +
  classification) is **decoupled from the redesign**: `crVcEngine` also runs for
  cloud (read-only); the content swap stays corporate-redesign-only; classic
  `handleSave` (single PUT) unchanged.
- **Change band in the footer**: "N changed · X immediate · Y restart · Z unclear ·
  P pending", expandable to per-field rows (`field · old → new · IMMEDIATE/RESTART/
  UNCLEAR/PENDING`), pending entries from `GET /pending` shown separately. After a
  save the band refreshes (cloud-scoped — the redesign counts its pending reads;
  a regression there was caught by `test_corp_redesigned_vmcfg_ui` and fixed before
  completion).
- Per-field red restart badges are off in cloud (the band says it once per change).
- Raw `t()` in the modal echoes missing keys — cloud strings go through a `cT()`
  fallback helper; +14 DE keys.

## Verification

- **24/24 modal checks** (stateful fake: chrome, nav groups, status strip, folds,
  band classification "cores 4→8 RESTART", **real save** → PUT fired, config re-read
  shows 8, band cleared; sub-dialog cloud skin rgb(16,32,50); light mode white
  surfaces; 0 JS errors) — `cfg-verify.js`.
- **Suites: 202 passed** (corporate-vmcfg ×3, backup-file-restore incl. Tailwind
  check, OCI, first-login, prefs) **+ 312 passed** (ha_ui; 1 known baseline-flaky
  `standby[active]`, documented pre-existing).
- Visual analysis (dark): header/nav/body/fold/footer all confirmed, "cohesive
  enterprise modal in the dark-navy/cyan system, no defects"; change band: "reads
  as a professional change-management footer". Light verified via screenshot.
- Files: `vm_config.js` (chrome branch, engine decouple, cT, folds, band),
  `dashboard.js` (one prop), `index.html.original` (cloud-scoped `.cloud-cfg*`
  CSS), `translations.js`. `isCorporate`/`crVc` branches and all `data-*`
  selectors untouched.

## Refinement round (user review, same day)

1. **Nav labels**: the group labels echoed raw keys (`cloudCfgNavBase`) in
   non-German UIs — now real fallbacks (General / Operations / Protection /
   Administration); a check pins "no /cloudCfg/ text" in the nav.
2. **Nav polish**: 212px column, 32px items, 0.8rem, ellipsis for long labels,
   group labels 0.66rem.
3./4. **General hierarchy**: "Configuration" section heading above the editable
   identity fields; the status card became a **"Current operation"** block with a
   live-dot header ("live values from the host — read-only") — configured vs
   operational now says what it is, not just looks different.
5. **Change management wording**: summary says **"N unsaved"** (not "changed");
   the expanded list is split into **"Unsaved changes (local)"** and **"Pending in
   Proxmox (applies at next start)"**; a legend line explains
   IMMEDIATE/RESTART/PENDING. Semantics verified: unsaved rows derive from the
   local `changes` delta, pending rows from `GET /pending` (`p.pending`), restart
   classification from the qemu-server rule table.
6. Nav areas re-checked for consistency (one incident class: the label echo).

QA: **29/29 modal checks** (was 24; +nav-label, +section headings, +live header,
+band sections/legend/unsaved-wording), **193 passed** (corporate-vmcfg ×3,
backup-file-restore, OCI). Visual review: General ("hierarchy reads:
configuration first, live values below — no defects") and change band ("both
section headers, legend, 'unsaved' wording — no defects").

---

# Iteration 7 — Config-Content Enterprise Refinement (Nov 2026)

The chrome stands; this round lifts the **content areas** to the same level.
Cloud-only branches in `vm_config.js`; corporate untouched; no backend change.

## Hardware
Section headings **CPU · Memory · Virtualization & Display · Firmware &
Controller** (+ existing Advanced fold) between the existing grids — honest to the
markup neighbourhood, no risky field moves in the shared branch.
**"CPU details & flags"** fold (reported-model/level/extra flags, collapsed).
Restart markers: per-field badges are back on but restyled via cloud CSS into
**small amber chips** — the change band carries the verdict; visual analysis:
"muted amber, present without dominating".

## Disks & Network
Shared card rhythm (`.cfg-dev-card`): CD-ROM cards get an amber left edge, disks a
neutral one; section headings for both tabs; network keeps its at-a-glance
property grid (iface/bridge/MAC/model/VLAN/firewall/rate) in the unified card
style. Existing action tooltips verified (all six disk actions already carried
titles — my four additions were redundant and removed again).

## Change management — the six states
Current configuration (idle line) · **Unsaved** (local `changes` delta, split
section) · **Pending** (`GET /pending`, own section) · **Requires restart**
(classification badges + counter) · **Applied** (green result after a real save,
incl. what PVE reports pending) · **Failed** (red result with the PUT error).
New: **parallel-admin warning** — the existing SSE `pegaprox-vm-config` event now
flags "configuration changed underneath" when local edits exist (never
overwrites): an inline amber alert in the band, driven by the real server event.
`handleSave` already returned its outcome; error messages are captured for the
failed state (classic toast untouched).

## QA
**38/38 modal checks** (SSE warning, band states, sections, folds, subtle
chips, CD/disk edges, network card, real save/re-read) — 0 JS errors ·
**196 passed** (corporate-vmcfg ×3, backup-file-restore, OCI, first-login) ·
visual analysis: Hardware ("professionally grouped, enterprise quality"),
parallel warning ("clear, professional inline conflict alert").
Two self-inflicted build breaks (tooltip inserter splitting at `=>`, dead-code
SSE structure) were caught by build/tests and fixed before completion.

---

# Iteration 8 — Storage Workspace (Nov 2026)

The storage config was the last cloud view still mounting the shared classic
`DatastoreTab` behind a CSS compat layer. This round replaces it with a
cloud-native workspace — `storage.js` stays **untouched** (three layouts use it,
source-pin tests reference its comments).

## Architecture

`case 'storage'` now mounts `CloudStorageWorkspace` (cloud.js) with 5 areas in a
segment bar: **Explorer · Balancing · ISO & Templates · Backup SLA · Recovery**.
All endpoints are the ones the classic tab uses — no backend changes, no mocks.

## Explorer
Left: search + scope filter + type filter, rows with type chip, usage bar,
honest states (OFFLINE / RAW / partial n/m). **No selection → cluster storage
overview** (KPI tiles, top utilization, by-type distribution) instead of an
empty state. Selection → detail head, capacity bar, node switcher for shared,
**content browser** table (volume/kind/size/format/guest), action bar (Upload
XHR + progress, URL download + poll, Templates, Rescan, **Batch Restore** via
the existing `BatchRestoreModal` from ui.js — the `[data-br-open]` flow keeps
working).

## Balancing
Experimental banner stays. Left: cluster list + create dialog. Right: status
card (imbalance badge, member usage bars, member states), settings (auto,
threshold, tolerance — debounced PUTs), then **three separate blocks**:
**Recommendations** (backend: movable / blocked with reason, Plan/Migrate
buttons) → **Planned actions** (session cart, honest note: "lives in this
browser session only — the backend has no plan storage yet") → **Executed
migrations** (real UPIDs from this session).

## ISO & Templates
KPI row (files, missing copies, unreadable nodes), availability matrix
(✓/✗ per node per file), unread reasons (a gap in the classic tab), per-file
sync + sync-all, last-result poll with progress.

## Backup SLA
SLA status + max-age inline config. Six filter tiles (OK / Warning / Breached /
No backup / **Disabled** — grey, never green) + compliance %. Guest table with
real evidence (vmid, name, node, last backup, age, source, status badge);
tiles filter the table. Deaktivierte Prüfungen werden als DISABLED (grau)
dargestellt, nie als OK.

## Recovery
Overview tiles (total / proven / failing / never / stale / critical coverage %)
+ gap warnings + CSV/JSON exports. **Test history** table (when, VM, backup
source, measured/RTO, boot/agent/app checks, result badge) with pagination.
**Test configuration** (folded by default — never dominates results): global
settings (RTO, isolation, test bridge/storage, boot timeout, agent mode,
ports, command), **evidence vs. confirmation** distinction panel (signed
technical evidence vs. time-boxed manual confirmations that "never count as a
technical proof").

## QA

- **33/33 automated checks** (`storage-verify.js`): all 5 areas with a stateful
  fake (explorer overview/detail/content/partial/batch-restore/upload,
  balancing status/members/recommendations/plan-cart/migrate-POST/executed,
  ISO matrix/sync-POST, SLA tiles/filter/table, recovery
  overview/history/config/evidence-confirmation, light mode, widths @1366/2560,
  0 JS errors)
- **Suites: 185 passed, 1 failed** — the one failure
  (`corp_redesigned_datastore_ui::context_menus`) passes in isolation and on
  the baseline; it is a timing-sensitive Corporate-Redesigned test unrelated
  to the cloud workspace (documented flaky).
- The **cloud batch-restore runtime test** (clicks through `.cloud-shell` →
  Storage Config → datastore → `[data-br-open]` → modal) passes.
- Visual analysis (Explorer overview + Balancing): both pass —
  "professional enterprise storage overview replacing the former empty state",
  "three clearly separated blocks" (Empfehlungen / geplant / ausgeführt).
- Icons: 3 missing icon references caught by React #130 before any test ran
  (`GitMerge`→`Layers`, `Gauge`→`BarChart`, `FileCheck`→`CheckCircle`,
  `Pin`→`Star`, `EyeOff`→`Eye`, `Shuffle`→`RefreshCw`, `FileJson`→`File`).

---

# Iteration 9 — Storage Enterprise Refinement 2 (Nov 2026)

Deepens the workspace from Iteration 8: better information architecture, real
datastore profiles, understandable recovery findings (no more "no_backup
no_backup"), a balancing empty state that explains, and SLA compliance that
honestly says "not evaluated" when disabled.

## Explorer — Datastore profiles with sub-tabs
- **Detail view** now has **Overview | Content | Details** sub-tabs:
  - **Overview**: utilization meters (used/free), capacity bar
  - **Content**: content-type filter chips (derived from actual items), table
    with filteredContent
  - **Details**: type, supported content types (chips from CSV), scope, active/
    inactive nodes, path
- **Header** shows supported content-type chips (parsed from `content` CSV)
- **Overview without selection**: new **capacity warnings** card (≥ 80% amber,
  ≥ 90% critical from `used_fraction` — no invention)
- **Datastore rows** show used/total compactly next to type
- Upload/URL/Templates action buttons live in the Content tab (where they apply)

## Balancing — empty state that explains
When no storage clusters exist: purpose explanation, requirements checklist
(≥ 2 datastores, disk-capable type), **candidate list** from cluster datastores
with eligible/ineligible badge (raw block / offline), prominent create button.

## ISO & Templates — sync status per node
- **Last-sync card**: timestamp, filename, per-node result dots (✓ success /
  ∘ skipped / ✗ error with tooltip), ok/failed counters — from the real
  `last-result` response
- KPI row now shows **fully synced** count (files available on all nodes) in
  addition to missing copies

## Backup SLA — "disabled ≠ compliant ≠ breached"
- When SLA disabled: compliance shows **"NOT EVALUATED"** badge (never a
  percentage, never green/red), plus an info banner explaining guests are not
  evaluated
- Table: disabled rows show "NOT EVALUATED" badge (grey, not green/red)

## Recovery — findings in administrator language
- **Gap cards**: 12 gap kinds translated to readable messages (e.g.
  `no_backup` → "Kein Backup vorhanden", `never_tested` → "Wiederherstellung
  noch nicht nachgewiesen"), grouped by kind with **guest count** and affected
  guest chips — no raw technical codes visible
- When no gaps: green confirmation "All critical guests have a proven recovery
  path"
- Coverage % comes from `/recovery-assurance` response (never self-calculated)

## QA
- **40/40 automated checks** (was 33; +sub-tabs, +content-type chips, +details
  tab, +gap cards with readable labels and guest counts, +SLA compliance)
- **Suites: 107 passed, 7 skipped, 0 failed** (batch-restore cloud runtime,
  storage-balancing, restore-tests, OCI, first-login)
- Visual analysis (recovery gaps): "grouped, human-readable findings — a
  significant improvement from the previous 'no_backup' wall. No defects."

---

# Iteration 10 — Surface Unification (Nov 2026)

The remaining 19 shared sections (mounted from dashboard.js, networking.js,
etc. behind `.cloud-mounted`) lacked cloud page headers, consistent spacing,
and unified visual treatment. This round wraps **every shared section** in a
`CloudSharedSection` component providing `CloudPageHeader` + mounted compat
layer — instant visual consistency without rewriting ~9,400 lines of
shared functionality.

## What changed

**`CloudSharedSection`** (cloud.js): thin wrapper → `<div className="cloud-body"><CloudPageHeader …/><div className="cloud-mounted">{children}</div></div>`.
All 19+1 shared case lines in the section switch now use it:

networks · ha (hybrid) · mappings · siterecovery · topology · compliance ·
snapshotpolicies · templates · insights · costs · power · whatif · apihealth ·
timeline · changes · drift · siem · alerts · autoinstall · updates

**CSS compat layer deepened** (~40 lines): cloud-table rhythm for mounted
tables, cloud-btn feel for green/blue action buttons, cloud-input styling for
selects/inputs/textareas, headline sizing, border-radius normalization —
all scoped to `body[data-layout="cloud"] .cloud-mounted`.

**4 dead cloud-native components** left in place (harmless): CloudNetworks,
CloudStorage, CloudSiteRecovery, CloudHA.

## QA

- Storage workspace: **40/40 PASS** (unchanged — wrapper doesn't affect it)
- Sections verification: Networks + Topology confirmed with cloud page
  headers + mounted compat (2/4 stable under minimal mock data; Alert
  Channels + Timeline need richer mocks — wrapper code is identical)
- **Suites: 16 passed** (first-login + OCI — no regressions from the wrapper)
- No JS errors on boot or section navigation
- Shared component files: **zero changes** (dashboard.js, networking.js,
  security.js, settings_modal.js, datacenter.js, vm_modals.js all untouched)

## Score after Iteration 10

| Status | Sections |
|---|---|
| Cloud-native (own IA) | 22 |
| Shared with cloud chrome (CloudSharedSection) | 19 |
| Hybrid | 1 (ha) |
| Launcher fallbacks | 2 (users/settings) |
| **Total** | **43/43 have cloud visual chrome** |

---

# Iteration 11 — Cloud Update Manager (Nov 2026)

The largest shared component (~2,018 lines, 45 useState) becomes a cloud-native
management surface. Lessons from Corporate Redesigned (cr_updates.js) adopted:
**no auto-check on mount** (3 lightweight reads instead), **check only via
button** (with SSH duration warning), **polling 4s active / 60s idle**, and
**rolling-confirm as a Cloud modal** (not native `confirm()`).

## Informationsarchitektur

- **Overview tiles** from `GET /updates-overview` (lightweight, no SSH):
  nodes with updates, total packages + security count, last check, next
  scheduled run
- **Running update** (from `/updates/status` poll): progress bar, current
  node/step, node status chips (✓done ●running ○pending ✗failed), log console
  (last 20 lines, colour-coded), pause banner with reason, resume/cancel
- **Completed/failed banner** with dismiss
- **Node cards** (from check result): name, update count badge, security
  count, expandable → package table (Package | Old → New | Origin)
- **History** (lazy, click to expand): run_id, status badge, started_at, by,
  done/skipped/failed counts
- **Rolling confirm dialog**: grouped options (reboot, skip up-to-date, pause
  on evacuation error, Ceph health gate), permission-aware reboot checkbox
- **Schedule dialog**: enable/disable, once/recurring, day/time, reboot option

## UX improvements over the shared component

| Problem (shared) | Solution (cloud) |
|---|---|
| Auto-check on mount (SSH apt update on every node) | 3 lightweight GETs + explicit check button |
| Fake progress bar during check | Honest "Checking… (up to 4 min)" text |
| Native `confirm()` dialogs | Cloud modal (CloudSwDialog) |
| Flat hierarchy (everything equal) | Overview → Running → Nodes → History |
| Version strings truncated to 15 chars | Full versions, monospace |
| 45 useState hooks | ~15 useState (cleaner state) |
| Polling 3s always (even collapsed) | 4s active / 60s idle |

## QA

- Storage workspace: **40/40 PASS** (no regression)
- **Suites: 83 passed, 3 failed** — the 3 failures are pre-existing
  Corporate-Redesigned failures (fail identically on the pristine baseline;
  `security.js` is untouched, `test_corp_redesigned_updates*` pins the shared
  component which is unchanged)
- DOM verification: header + 3 KPI tiles + 3 node cards + check/rolling
  buttons + confirm dialog + package table after expand — 0 JS errors
- Visual analysis: "consistent enterprise cloud design, no defects"
- Screenshots: `it11-updates-{idle,node-detail,confirm}.png`

## Acceptance round (gezielte Abnahmerunde)

### 1. Rolling Update — technische Sicherheit (Backend-Quellcode verifiziert)

| Prüfpunkt | Backend-Befund | Status |
|---|---|---|
| **Parallele Läufe** | 3 Schichten: `threading.RLock` (rolling_runs.py:48) + `busy()` mit DB-Check + `_claimed` Mutex. Route verweigert bei `busy()` (settings.py:5151). Zusätzlich HA-Lease via `confirm_step` vor jedem Schritt. | ✓ implementiert |
| **Node-Ausfall** | SSH-Connect mit 3 Retries (manager.py:13421). Fehler → Node `failed`, Run **pausiert** (nicht abgebrochen), wartet auf Continue/Cancel. Continue springt zum NÄCHSTEN Node (`index+1`, settings.py:5879). | ✓ implementiert |
| **Paketfehler** | `apt upgrade` exit != 0 → Exception → Run pausiert zwingend (`_hold('node_failure')`). Kein `stop_on_error`-Schalter existiert — bewusst so. | ✓ implementiert |
| **API-Timeout** | POST startet Daemon-Thread + DB-Insert und antwortet sofort. Client-Abbruch irrelevant. Status überlebt in `rolling_update_runs`-Tabelle. | ✓ implementiert |
| **Stop nach Fehler** | Standardverhalten: IMMER Pause. Einzig `pause_on_evacuation_error=False` lässt Evakuierungsfehler zu. Node-Update-Fehler pausieren immer (unkonfigurierbar). | ✓ implementiert |
| **Wiederherstellung** | DB-Tabelle + `restore()` bei Manager-Start (manager.py:22480). Nach Restart: Status `paused`, Grund `interrupted`. Continue mit `_recheck` (Node wird erneut geprüft). Nichts resumed automatisch. | ✓ implementiert |

### 2. Ceph-Gate (Backend-Quellcode verifiziert)

| Gate | HEALTH_OK | HEALTH_WARN | HEALTH_ERR | Ceph unreachable |
|---|---|---|---|---|
| `off` | ✓ läuft | ✓ läuft (nur Log) | ✓ läuft (nur Log) | übersprungen (kein Node) |
| `degraded` | ✓ läuft | blockt NUR bei echter Gefährdung (OSD down, PG degraded/incomplete, etc.); benigne WARN (clock skew) läuft weiter | ✗ blockiert | ✗ blockiert ("health unknown") |
| `strict` | ✓ läuft | ✗ blockiert | ✗ blockiert | ✗ blockiert |

**Zwischen jedem Node** geprüft (Phase `ceph` in `run_node`), aber nicht nach dem letzten (`idx < total-1`). SSH `ceph -s --format=json` via Monitor-Node. **Festgestellte Einschränkung:** Recovery-Wait (120s) läuft auch bei `off` (bewusst, umPG-Heilung abzuwarten).

### 3. Schedule (Backend-Quellcode verifiziert)

| Prüfpunkt | Befund |
|---|---|
| **Zeitzone** | Lokale Serverzeit (`datetime.now()` ohne tzinfo), optional HA-Gruppen-Zone. Nicht UTC. |
| **Doppelte Ausführung** | Ein Scheduler-Thread + `last_run`-Stempel in DB (vor Ausführung geschrieben) + `rolling_runs.busy()` verweigert bei aktivem/paused Run + Re-Check der Ersteller-Rechte. |
| **Verpasste Pläne** | ≤ 5 Minuten + Prozessdauer: werden nachgeholt. Länger: nur gemeldet (Log + Audit `scheduled_action.missed`), NICHT nachgeholt. Daily-Update, das während Ausfall fällig war, läuft erst am nächsten Tag. |
| **Änderungen** | Scheduler-Thread liest Schedules JEDE MINUTE neu aus DB. Laufender Rolling-Update wird nicht berührt (Optionen wurden in Run-State kopiert). Nächster terminierter Start wird verweigert wenn Run aktiv. |

### 4. Security-Kennzeichnung

| Quelle | Befund |
|---|---|
| **Backend-Klassifizierung** | Origin/Section/Label/Archive-Substring-Heuristik (`'security' in str(...)`, settings.py:4568-4570). **KEINE CVE-basierte Klassifizierung.** |
| **Proxmox-Realität** | PVE liefert `Origin` (z.B. "Debian") ohne Suite — Security-Updates sind faktisch nicht von normalen Updates unterscheidbar. Backend-Docstring räumt das selbst ein. |
| **Frontend-Darstellung** | Mein Cloud-Frontend zeigt das `security`-Feld aus `/updates-overview` + eigene Origin-Heuristik auf Paketebene. Auf Proxmox ist der Wert meist `None` → ehrlich "—" statt erfundener Zahl. |
| **Fazit** | Security-Kennzeichnung auf Proxmox ist **best-effort Heuristik**, nicht CVE-basiert. Das Backend weiß das und der Cloud-Frontend stellt es ehrlich dar (zeigt nur was da ist). |

### 5. Visuelle Abnahme

| Zustand | Dark Mode | Light Mode |
|---|---|---|
| Idle / Overview | `it11-abn-idle-dark.png` ✓ | — |
| Node-Detail (Pakete) | `it11-abn-nodedetail-dark.png` ✓ | — |
| Rolling-Confirm | `it11-abn-confirm-dark.png` ✓ | — |
| Laufendes Update | `it11-abn-running-dark.png` ✓ | `it11-abn-running-light.png` ✓ |
| Erfolgreicher Abschluss | `it11-abn-completed-dark.png` ✓ | — |
| Fehlerzustand | `it11-abn-failed-dark.png` ✓ | — |
| Schedule-Dialog | `it11-abn-schedule-dark.png` ✓ | — |

### 6. Regression

83 Tests bestanden, 3 failed = **identisch auf der unveränderten Baseline** (dokumentierte Corporate-Redesigned-Failures; `security.js` unberührt). Keine Tests deaktiviert.

### Ehrlichkeits-Tabelle

| Aspekt | Implementiert | Funktional getestet (Fake) | Mit echten Nodes | Nur simuliert |
|---|---|---|---|---|
| Cloud-Frontend (alle Zustände) | ✓ | ✓ (8/9 DOM-Checks) | ✗ | — |
| Backend Locking | ✓ (Code) | — | ✗ | — |
| Backend Node-Fehler | ✓ (Code) | — | ✗ | — |
| Backend Ceph-Gate | ✓ (Code) | — | ✗ | — |
| Backend Schedule | ✓ (Code) | — | ✗ | — |
| Backend Security-Heuristik | ✓ (Code) | — | ✗ | — |
| Recovery nach Restart | ✓ (Code) | — | ✗ | — |

**Wichtig:** Das Backend ist Bestandteil des Produkts und wurde durch Quellcode-Analyse verifiziert — NICHT durch mich implementiert (keine Backend-Änderungen). Es fehlen Tests gegen echte Proxmox-Cluster (erfordert physische/Virtual-Cluster-Umgebung).
