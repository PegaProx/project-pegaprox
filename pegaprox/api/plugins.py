# -*- coding: utf-8 -*-
"""
PegaProx Plugin Management API - Layer 6
NS: Mar 2026 - auto-discover plugins from plugins/ dir, enable/disable via Settings

Plugins register route handlers via register_plugin_route() which are dispatched
through a single catch-all Flask route. This avoids Flask's restriction on
registering blueprints after the first request — plugins can be loaded at runtime.
"""

import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import threading
import logging
import importlib.util
from pathlib import Path
from datetime import datetime
from flask import Blueprint, jsonify, request, current_app

from pegaprox.constants import PLUGINS_DIR
from pegaprox.globals import *
from pegaprox.models.permissions import ROLE_ADMIN
from pegaprox.core.db import get_db
from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import safe_error

bp = Blueprint('plugins', __name__)

# NS May 2026 (#381 pentest) — strict path-segment whitelist for frontend_route
# values. One segment between slashes; alphanumerics + . _ - only.
_SAFE_PATH_SEG = re.compile(r'^[A-Za-z0-9_.-]+$')

# in-memory registries — guarded by _plugin_lock to prevent
# "dictionary changed size during iteration" crashes that made plugins
# appear to vanish under load (several users reported this).
_plugin_lock = threading.RLock()
_loaded_plugins = {}   # {plugin_id: module}
_plugin_routes = {}    # {plugin_id: {path: handler_fn}}
# the app the plugins were loaded into at startup, for a standby that follows the
# leader's plugin state later (follow_synced_state)
_app = None


# NS Apr 2026 — CodeQL flagged plugin_id as a path-injection vector (admin-only
# endpoints but still). Every endpoint below now passes plugin_id through this
# validator before touching the filesystem. Allowed chars match what
# `_discover_plugins` accepts — directory-name-safe ASCII only, no dots.
import re as _re
_PLUGIN_ID_RE = _re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')

def _valid_plugin_id(pid):
    return isinstance(pid, str) and bool(_PLUGIN_ID_RE.match(pid))


# ---- Plugin Route Registration (used by plugins) ----

def register_plugin_route(plugin_id, path, handler):
    """Register a route handler for a plugin. Called from plugin's register() function."""
    with _plugin_lock:
        _plugin_routes.setdefault(plugin_id, {})[path] = handler


# ---- Catch-all route for plugin API calls ----

@bp.route('/api/plugins/<plugin_id>/api/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@require_auth(perms=['plugins.view'])
def plugin_proxy(plugin_id, subpath):
    """Dispatch API requests to loaded plugins"""
    if not _valid_plugin_id(plugin_id):
        return jsonify({'error': 'Invalid plugin id'}), 400
    with _plugin_lock:
        if plugin_id not in _loaded_plugins:
            return jsonify({'error': 'Plugin not loaded'}), 404
        handler = _plugin_routes.get(plugin_id, {}).get(subpath)

    if not handler:
        return jsonify({'error': f'Route not found: {subpath}'}), 404

    try:
        result = handler()
        if isinstance(result, dict) or isinstance(result, list):
            return jsonify(result)
        return result
    except Exception as e:
        logging.error(f"[PLUGINS] {plugin_id}/{subpath} error: {e}")
        return jsonify({'error': 'Plugin request failed'}), 500


# ---- Discovery & State ----

def _discover_plugins():
    """Scan plugins/ dir for subfolders with manifest.json"""
    found = []
    plugins_path = Path(PLUGINS_DIR)
    if not plugins_path.exists():
        return found

    for d in sorted(plugins_path.iterdir()):
        if not d.is_dir() or d.name.startswith(('_', '.')):
            continue
        manifest_file = d / 'manifest.json'
        if not manifest_file.exists():
            continue
        try:
            with open(manifest_file, 'r') as f:
                meta = json.load(f)
            meta['_id'] = d.name
            meta['_dir'] = str(d)
            meta['_has_init'] = (d / '__init__.py').exists()
            found.append(meta)
        except Exception as e:
            logging.warning(f"[PLUGINS] Bad manifest in {d.name}: {e}")
            found.append({
                '_id': d.name, '_dir': str(d), '_has_init': False,
                'name': d.name, 'error': f'Invalid manifest: {e}'
            })

    return found


# MK Sep 2026 (#642) - a cluster id as it appears in the URL of every cluster route.
_SAFE_CLUSTER_ID = re.compile(r'^[A-Za-z0-9_-]{1,64}$')


def _parse_cluster_scope(raw):
    """Stored form ('a,b') to list. Empty / missing / NULL all mean every cluster."""
    if not raw:
        return []
    return [c for c in (part.strip() for part in str(raw).split(',')) if c]


def _get_plugin_states():
    db = get_db()
    rows = db.query('SELECT plugin_id, enabled, loaded_at, error, clusters FROM plugin_state') or []
    out = {}
    for r in rows:
        state = dict(r)
        state['clusters'] = _parse_cluster_scope(state.get('clusters'))
        out[state['plugin_id']] = state
    return out


def plugin_runs_here(plugin_id):
    """Whether plugin_id is loaded in this process and its plugin_state row says it is
    switched on. MK Oct 2026 (#625) - on a standby the row is the leader's, it syncs; the
    module stays loaded here until a restart when the leader switches the plugin off, so
    being loaded alone says nothing. False when the row cannot be read."""
    if not _valid_plugin_id(plugin_id):
        return False
    with _plugin_lock:
        if plugin_id not in _loaded_plugins:
            return False
    try:
        row = get_db().query_one('SELECT enabled FROM plugin_state WHERE plugin_id = ?', (plugin_id,))
    except Exception as e:
        logging.warning(f"[PLUGINS] could not read the state of {plugin_id}: {e}")
        return False
    return bool(row and row['enabled'])


def _set_plugin_state(plugin_id, enabled, error=''):
    db = get_db()
    now = datetime.now().isoformat()
    existing = db.query_one('SELECT plugin_id FROM plugin_state WHERE plugin_id = ?', (plugin_id,))
    if existing:
        db.execute('UPDATE plugin_state SET enabled = ?, loaded_at = ?, error = ? WHERE plugin_id = ?',
                   (1 if enabled else 0, now, error, plugin_id))
    else:
        db.execute('INSERT INTO plugin_state (plugin_id, enabled, loaded_at, error) VALUES (?, ?, ?, ?)',
                   (plugin_id, 1 if enabled else 0, now, error))


# ---- Loading ----

def load_plugin(app, plugin_id):
    """Load a plugin module and call its register() function
    WARNING: Plugins execute arbitrary Python with full process privileges.
    Only load plugins from trusted sources. There is no sandbox.
    NS Apr 2026: idempotent — if already loaded, return success without re-registering."""
    # NS May 2026 (Aikido SAST hardening) — defense-in-depth on plugin_id.
    # All API entry points already validate via _valid_plugin_id, but if a
    # future caller bypasses that we still refuse a path-traversal name here.
    if not _valid_plugin_id(plugin_id):
        return False, 'Invalid plugin id'
    # idempotency — re-enable clicks used to double-register routes
    with _plugin_lock:
        if plugin_id in _loaded_plugins:
            return True, ''

    plugins_root = Path(PLUGINS_DIR).resolve()
    plugin_dir = (plugins_root / plugin_id).resolve()
    # belt + suspenders: ensure resolved path is still under plugins/.
    try:
        plugin_dir.relative_to(plugins_root)
    except ValueError:
        return False, 'Plugin path escapes plugins root'
    init_file = plugin_dir / '__init__.py'

    if not init_file.exists():
        return False, 'No __init__.py found'

    # NS: check manifest for trusted flag — warn if missing
    manifest_path = plugin_dir / 'manifest.json'
    is_trusted = False
    if manifest_path.exists():
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            is_trusted = manifest.get('author', '').startswith('PegaProx')
        except Exception:
            pass
    if not is_trusted:
        logging.warning(f"[PLUGINS] [SECURITY] Loading UNTRUSTED plugin '{plugin_id}' — not authored by PegaProx Team. Review code before use!")
    # MK: Apr 2026 — security audit: plugins run with FULL process privileges, no sandbox
    # this is by design (like Grafana/Jenkins plugins) but must be documented
    from pegaprox.utils.audit import log_audit
    try: log_audit('system', 'plugin.load', f"Plugin '{plugin_id}' loaded (trusted={is_trusted})")
    except: pass

    try:
        mod_name = f'plugins.{plugin_id}'
        spec = importlib.util.spec_from_file_location(mod_name, init_file)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)

        # plugin calls register_plugin_route() inside register()
        if hasattr(mod, 'register'):
            mod.register(app)

        with _plugin_lock:
            _loaded_plugins[plugin_id] = mod
        logging.info(f"[PLUGINS] Loaded: {plugin_id}")
        return True, ''

    except Exception as e:
        logging.error(f"[PLUGINS] Failed to load {plugin_id}: {e}")
        # roll back partial state — a register() that half-succeeded can leave
        # stale routes referencing a module we're about to drop
        with _plugin_lock:
            _plugin_routes.pop(plugin_id, None)
            _loaded_plugins.pop(plugin_id, None)
        if f'plugins.{plugin_id}' in sys.modules:
            del sys.modules[f'plugins.{plugin_id}']
        return False, str(e)


def unload_plugin(plugin_id):
    """Unload a plugin — remove routes and module"""
    with _plugin_lock:
        _plugin_routes.pop(plugin_id, None)
        _loaded_plugins.pop(plugin_id, None)
    mod_name = f'plugins.{plugin_id}'
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    logging.info(f"[PLUGINS] Unloaded: {plugin_id}")


def seed_bundled_plugins():
    """Bring the plugins the image ships (PEGAPROX_PLUGINS_SEED) into PLUGINS_DIR: code
    replaced, a plugin's config.json and a plugin the admin added left alone. MK Oct 2026
    (#1134) - the Docker image loads its plugins from the config volume, so a new image
    no longer resets their settings. Unset everywhere else (the .deb postinst, update.sh
    and deploy.sh run the same sync)."""
    seed = os.environ.get('PEGAPROX_PLUGINS_SEED', '').strip()
    if not seed or not os.path.isdir(seed):
        return
    if os.path.realpath(seed) == os.path.realpath(PLUGINS_DIR):
        return
    # the sync script ships with the code, not with the plugins
    app_root = Path(__file__).resolve().parents[2]
    script = app_root / 'packaging' / 'plugins' / 'sync_plugins.py'
    try:
        spec = importlib.util.spec_from_file_location('pegaprox_sync_plugins', script)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.sync(seed, PLUGINS_DIR, say=lambda msg: logging.info(f"[PLUGINS] {msg}"))
    except Exception as e:
        logging.warning(f"[PLUGINS] could not bring the bundled plugins into {PLUGINS_DIR}: {e}")


def load_enabled_plugins(app):
    """Called once at startup — load all enabled plugins"""
    global _app
    _app = app
    seed_bundled_plugins()
    states = _get_plugin_states()
    discovered = _discover_plugins()

    loaded = []
    for plugin in discovered:
        pid = plugin['_id']
        state = states.get(pid, {})
        if state.get('enabled'):
            ok, err = load_plugin(app, pid)
            if ok:
                loaded.append(plugin.get('name', pid))
                # clear any old error from the DB
                _set_plugin_state(pid, True, error='')
            else:
                # keep enabled flag so user still sees the intent, record error for UI
                _set_plugin_state(pid, True, error=err)

    if loaded:
        logging.info(f"[PLUGINS] {len(loaded)} plugin(s) loaded: {', '.join(loaded)}")


def follow_synced_state():
    """A standby, after a sync: load the plugins the leader has switched on and unload the
    ones it switched off, so a plugin runs here exactly when the leader says so. MK Oct
    2026 (#625) - a standby starts before its first sync, and the plugin state that sync
    brings was never acted on. Writes nothing (plugin_state is the leader's) and starts
    no background tasks (only an active one runs those). Returns (loaded, unloaded)."""
    if _app is None:
        return [], []
    states = _get_plugin_states()
    wanted = {pid for pid, st in states.items() if st.get('enabled') and _valid_plugin_id(pid)}
    with _plugin_lock:
        running = set(_loaded_plugins)
    loaded, unloaded = [], []
    for pid in sorted(running - wanted):
        unload_plugin(pid)
        unloaded.append(pid)
    for pid in sorted(wanted - running):
        ok, err = load_plugin(_app, pid)
        if ok:
            loaded.append(pid)
        else:
            logging.warning(f"[PLUGINS] the leader runs {pid}, this instance could not load it: {err}")
    return loaded, unloaded


def start_plugin_backgrounds():
    # MK Oct 2026 (#625) - automatic failover: a plugin's background task asks nobody,
    # so it starts only where this instance may act. In the leader's process that may
    # not act yet (the takeover wait) it starts once it may; on a leader on disk whose
    # process is not the acting one (no lease state to run) it does not start at all.
    # In a manual group nothing changes: main() calls this on no standby
    from pegaprox.core import ha
    if not ha.is_active():
        if ha.acting_process():
            ha.when_active(start_plugin_backgrounds, 'plugin-backgrounds')
        else:
            logging.warning("[PLUGINS] background tasks not started: this instance may not act")
        return
    # snapshot under lock to avoid "dictionary changed size during iteration"
    with _plugin_lock:
        plugins_snapshot = list(_loaded_plugins.items())
    for pid, mod in plugins_snapshot:
        if hasattr(mod, 'start_background_tasks'):
            try:
                mod.start_background_tasks()
                logging.info(f"[PLUGINS] Background tasks started for {pid}")
            except Exception as e:
                logging.error(f"[PLUGINS] Background task failed for {pid}: {e}")


# ---- API Routes ----

@bp.route('/api/plugins', methods=['GET'])
@require_auth(perms=['plugins.view'])
def list_plugins():
    """List all discovered plugins with their enabled/disabled state"""
    discovered = _discover_plugins()
    states = _get_plugin_states()

    result = []
    # snapshot the registries so the list is consistent even if enable/disable runs mid-request
    with _plugin_lock:
        loaded_snapshot = set(_loaded_plugins.keys())
        routes_snapshot = {k: list(v.keys()) for k, v in _plugin_routes.items()}

    for plugin in discovered:
        pid = plugin['_id']
        state = states.get(pid, {})
        # NS May 2026 (#381) — surface the manifest's frontend hook so the
        # dashboard can build a plugin tab without core changes per plugin.
        # Sanitize: route must be a string starting with /api/plugins/<pid>/
        # so a malicious manifest can't redirect the iframe to an external host.
        has_frontend = bool(plugin.get('has_frontend', False))
        raw_route = plugin.get('frontend_route', '')
        frontend_route = ''
        # NS May 2026 (#381) — strict route validation. Accept either:
        #   1. fully-qualified plugin path: /api/plugins/<pid>/api/...
        #   2. pure relative form: 'ui' or 'admin/dash' → scoped under us
        # Reject anything else: external URLs, protocol-relative, absolute
        # paths to other plugins, leading slash, control chars, query/fragment.
        # NS May 2026 (pentest follow-up) — additionally reject anything with
        # control chars (CRLF/null/tab), URL semantics (?, #, %, \), or
        # parent-segment traversal (..). These would otherwise land verbatim
        # in the iframe src and could enable URL/header injection downstream.
        def _is_safe_relative_path(s):
            if not s or not isinstance(s, str): return False
            if any(ord(c) < 0x20 or ord(c) == 0x7f for c in s): return False
            for bad in ('?', '#', '%', '\\', '*', ':', ' ', '\t'):
                if bad in s: return False
            for seg in s.split('/'):
                if not seg or seg in ('..', '.'): return False
                if not _SAFE_PATH_SEG.match(seg): return False
            return True

        if has_frontend and isinstance(raw_route, str):
            expected_prefix = f'/api/plugins/{pid}/'
            if raw_route.startswith(expected_prefix):
                tail = raw_route[len(expected_prefix):]
                if _is_safe_relative_path(tail):
                    frontend_route = raw_route
                else:
                    has_frontend = False
            elif raw_route and _is_safe_relative_path(raw_route):
                # 'ui' → /api/plugins/<pid>/api/ui — matches register_plugin_route()
                frontend_route = f'/api/plugins/{pid}/api/{raw_route}'
            else:
                has_frontend = False
        else:
            # non-string routes (number, dict, list, None) → drop entirely
            has_frontend = False
        result.append({
            'id': pid,
            'name': plugin.get('name', pid),
            'version': plugin.get('version', ''),
            'author': plugin.get('author', ''),
            'description': plugin.get('description', ''),
            'enabled': bool(state.get('enabled', 0)),
            'loaded': pid in loaded_snapshot,
            'error': state.get('error', '') or plugin.get('error', ''),
            'has_init': plugin.get('_has_init', False),
            'routes': routes_snapshot.get(pid, []),
            'trusted': plugin.get('author', '').startswith('PegaProx'),
            'has_frontend': has_frontend,
            'frontend_route': frontend_route,
            # #642 - empty list = every cluster; the frontend filters on this
            'clusters': state.get('clusters') or [],
        })

    return jsonify(result)


@bp.route('/api/plugins/<plugin_id>/reload', methods=['POST'])
@require_auth(perms=['plugins.manage'])
def reload_plugin(plugin_id):
    """Force-reload a plugin (unload + load). Helps when a plugin crashed
    and the user wants to retry without a full server restart."""
    if not _valid_plugin_id(plugin_id):
        return jsonify({'error': 'Invalid plugin id'}), 400
    plugins_path = Path(PLUGINS_DIR) / plugin_id
    if not plugins_path.exists() or not (plugins_path / 'manifest.json').exists():
        return jsonify({'error': 'Plugin not found'}), 404

    unload_plugin(plugin_id)
    ok, err = load_plugin(current_app._get_current_object(), plugin_id)
    _set_plugin_state(plugin_id, True, error=err)

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'plugins.reloaded', f"Reloaded plugin: {plugin_id}")

    if ok:
        mod = _loaded_plugins.get(plugin_id)
        if mod and hasattr(mod, 'start_background_tasks'):
            try: mod.start_background_tasks()
            except Exception: pass
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': err}), 500


@bp.route('/api/plugins/<plugin_id>/enable', methods=['POST'])
@require_auth(perms=['plugins.manage'])
def enable_plugin(plugin_id):
    """Enable and load a plugin at runtime"""
    if not _valid_plugin_id(plugin_id):
        return jsonify({'error': 'Invalid plugin id'}), 400
    plugins_path = Path(PLUGINS_DIR) / plugin_id
    if not plugins_path.exists() or not (plugins_path / 'manifest.json').exists():
        return jsonify({'error': 'Plugin not found'}), 404

    # load at runtime — no blueprint needed, uses catch-all route
    ok, err = load_plugin(current_app._get_current_object(), plugin_id)
    _set_plugin_state(plugin_id, True, error=err)

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'plugins.enabled', f"Enabled plugin: {plugin_id}")

    if ok:
        # start background tasks
        mod = _loaded_plugins.get(plugin_id)
        if mod and hasattr(mod, 'start_background_tasks'):
            try:
                mod.start_background_tasks()
            except Exception:
                pass
        return jsonify({'success': True, 'message': f'Plugin {plugin_id} enabled and loaded.'})
    else:
        return jsonify({'success': False, 'error': err}), 500


@bp.route('/api/plugins/<plugin_id>/disable', methods=['POST'])
@require_auth(perms=['plugins.manage'])
def disable_plugin(plugin_id):
    """Disable and unload a plugin"""
    if not _valid_plugin_id(plugin_id):
        return jsonify({'error': 'Invalid plugin id'}), 400
    unload_plugin(plugin_id)
    _set_plugin_state(plugin_id, False)

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'plugins.disabled', f"Disabled plugin: {plugin_id}")

    return jsonify({'success': True, 'message': f'Plugin {plugin_id} disabled.'})


@bp.route('/api/plugins/rescan', methods=['POST'])
@require_auth(perms=['plugins.manage'])
def rescan_plugins():
    """Rescan plugins/ directory for new or removed plugins"""
    discovered = _discover_plugins()
    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'plugins.rescan', f"Rescanned plugins directory: {len(discovered)} found")
    return jsonify({'success': True, 'count': len(discovered), 'message': f'{len(discovered)} plugin(s) found.'})


@bp.route('/api/plugins/<plugin_id>', methods=['DELETE'])
@require_auth(perms=['plugins.manage'])
def delete_plugin(plugin_id):
    """Unload, remove state, and delete plugin from disk"""
    if not _valid_plugin_id(plugin_id):
        return jsonify({'error': 'Invalid plugin id'}), 400
    import shutil
    plugins_path = Path(PLUGINS_DIR) / plugin_id
    if not plugins_path.exists():
        return jsonify({'error': 'Plugin not found'}), 404

    # unload if loaded
    unload_plugin(plugin_id)

    # remove DB state
    db = get_db()
    db.execute('DELETE FROM plugin_state WHERE plugin_id = ?', (plugin_id,))

    # delete from disk
    try:
        shutil.rmtree(str(plugins_path))
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Failed to delete plugin files')}), 500

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'plugins.deleted', f"Deleted plugin: {plugin_id}")

    return jsonify({'success': True, 'message': f'Plugin {plugin_id} deleted.'})


def plugin_file(plugin_id, filename):
    """A file of a plugin, from the directory the plugins are loaded from, as an absolute
    path - None for a bad id, a path that resolves out of the plugin's folder (a symlink,
    '..') and a file that is not there. MK Oct 2026 (#1134) - a plugin's own page was read
    next to the program files, where a package install has no plugins: the plugin ran
    and its page said "not installed". Same containment as load_plugin."""
    if not _valid_plugin_id(plugin_id) or not isinstance(filename, str) or not filename:
        return None
    root = Path(PLUGINS_DIR).resolve()
    plugin_dir = (root / plugin_id).resolve()
    path = (plugin_dir / filename).resolve()
    try:
        plugin_dir.relative_to(root)
        path.relative_to(plugin_dir)
    except ValueError:
        return None
    return path if path.is_file() else None


def _safe_plugin_path(plugin_id, filename='config.json'):
    """Validate plugin_id and return safe path — prevents path traversal"""
    if '..' in plugin_id or '/' in plugin_id or '\\' in plugin_id:
        return None
    resolved = (Path(PLUGINS_DIR) / plugin_id / filename).resolve()
    if not str(resolved).startswith(str(Path(PLUGINS_DIR).resolve())):
        return None
    return resolved


@bp.route('/api/plugins/<plugin_id>/clusters', methods=['PUT'])
@require_auth(perms=['plugins.manage'])
def set_plugin_clusters(plugin_id):
    """Limit a plugin to specific clusters (#642).

    An empty list puts it back on every cluster, which is where every plugin starts.
    Ids are not checked against the live cluster list on purpose: a cluster can be
    offline or added later, and dropping its id here would silently widen the scope
    back to everything the next time somebody saved.
    """
    if not _valid_plugin_id(plugin_id):
        return jsonify({'error': 'Invalid plugin id'}), 400
    if not any(p['_id'] == plugin_id for p in _discover_plugins()):
        return jsonify({'error': 'Plugin not found'}), 404

    data = request.get_json(silent=True) or {}
    raw = data.get('clusters', [])
    if not isinstance(raw, list):
        return jsonify({'error': 'clusters must be a list'}), 400
    clusters = []
    for entry in raw:
        if not isinstance(entry, str) or not _SAFE_CLUSTER_ID.match(entry):
            return jsonify({'error': f'Invalid cluster id: {entry!r}'}), 400
        if entry not in clusters:
            clusters.append(entry)

    db = get_db()
    stored = ','.join(clusters)
    existing = db.query_one('SELECT plugin_id FROM plugin_state WHERE plugin_id = ?', (plugin_id,))
    if existing:
        db.execute('UPDATE plugin_state SET clusters = ? WHERE plugin_id = ?', (stored, plugin_id))
    else:
        db.execute('INSERT INTO plugin_state (plugin_id, enabled, clusters) VALUES (?, 0, ?)',
                   (plugin_id, stored))

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'plugins.scope_changed',
              f"Plugin {plugin_id} limited to: {stored or 'all clusters'}")
    return jsonify({'success': True, 'clusters': clusters})


# MK Nov 2026 - the config editor showed every value as stored, the status page key and
# the notification token and apprise urls among them. Values under a key that names a
# credential go out masked, like the SMTP password in the settings, and a masked value
# that comes back is the stored one again.
_CONFIG_MASK = '********'
# a token, key, secret or password, a pwd, credential, webhook, dsn, bearer or cookie, with
# everything below it, whatever the name ends on (token_url, key_server)
_CONFIG_SECRET_HINTS = ('token', 'key', 'secret', 'password', 'passwd', 'pwd', 'credential',
                        'hook', 'dsn', 'bearer', 'cookie', 'apprise_url')
# smtp_pass, auth, authorization or mqtt.pw name a login too, unless an address word
# follows it in the name (auth_server, passive_port)
_CONFIG_LOGIN_HINTS = ('pass', 'authent', 'authoriz')
_CONFIG_LOGIN_WORDS = re.compile(r'(?<![a-z0-9])(?:pw|auth)(?![a-z0-9])')
# a name with one of these after its last secret word is an address (smtp_host, auth_server),
# unless the url carries the login itself (webhook_url, a dsn, apprise urls).
# A stored secret goes to the address it was typed for: a save that keeps one masked while
# it changes an address in the same object or in one below it, a port too, or puts a new
# one into a list there, has to name the secret again. A list entry that is a url itself
# (an apprise url) carries its address along, as does a secret under an address name.
_CONFIG_ADDRESS_HINTS = ('url', 'host', 'server', 'endpoint', 'addr', 'domain', 'proxy', 'broker',
                         'gateway', 'relay', 'conn_str', 'connection_str')
_CONFIG_ADDRESS_WORDS = re.compile(r'(?<![a-z0-9])(?:uris?|ports?|ip|ipv4|ipv6)(?![a-z0-9])|(?<![a-z0-9])base$')
_CONFIG_PORT_WORD = re.compile(r'(?<![a-z0-9])ports?(?![a-z0-9])')
# what an address is shown or used as names none itself (server_label, proxy_mode)
_CONFIG_NOT_ADDRESS = re.compile(
    r'(?<![a-z0-9])(?:label|title|mode|type|style|display|desc|description|version)(?![a-z0-9])')
_CONFIG_LOGIN_URLS = ('hook', 'dsn', 'apprise_url')
# a list entry is found by these, and shows them in clear below a secret name too
_CONFIG_ID_KEYS = ('id', 'name', 'label')
_CONFIG_SCHEME = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*$')
_CONFIG_URL = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\s]')
# the login a value carries under any name: postgres://user:pw@db, Password= of a connection
# string. A password may hold a / (u:pw/1@db), and a key a : (Jet OLEDB:Database Password)
_CONFIG_URL_LOGIN = re.compile(r'^(\s*[A-Za-z][A-Za-z0-9+.-]*://)(?:[^/]*|[^/@]*:[^@]*)@')
_CONFIG_CONN_KEY = re.compile(r'\s*[A-Za-z][A-Za-z0-9 _.:-]*\s*$')
_CONFIG_HANDLE = re.compile(r'#([0-9a-f]{16})([0-9a-f]{16})$')
# without the database key a handle holds for this process only
_CONFIG_PROCESS_KEY = secrets.token_bytes(32)
# a handle holds until the next write of that config.json, so whether an old one still
# finds its value says nothing about what a save since then held
_CONFIG_GENERATION = {}


class _CredentialRequired(ValueError):
    def __init__(self, fields, moved=()):
        super().__init__(', '.join(fields))
        self.fields = list(fields)
        self.moved = list(moved)


def _config_name(name):
    # ntfyToken reads as ntfy_token
    return re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', str(name)).lower()


def _key_path(path, k):
    return f'{path}.{k}' if path else str(k)


def _hint_at(n, hints, words):
    """Where the last of the hints or words starts in n, -1 for none."""
    at = max(n.rfind(h) for h in hints)
    for m in words.finditer(n):
        at = max(at, m.start())
    return at


def _is_address_name(name):
    """A name with an address word after its last secret word: smtp_host, auth_server,
    token_url, api_base."""
    n = _config_name(name)
    if any(h in n for h in _CONFIG_LOGIN_URLS):
        return False
    at = _hint_at(n, _CONFIG_ADDRESS_HINTS, _CONFIG_ADDRESS_WORDS)
    return at >= 0 and at > _hint_at(n, _CONFIG_SECRET_HINTS + _CONFIG_LOGIN_HINTS, _CONFIG_LOGIN_WORDS)


def _is_secret_name(name):
    n, low = _config_name(name), str(name).lower()
    if any(h in n or h in low for h in _CONFIG_SECRET_HINTS):
        return True
    return _hint_at(n, _CONFIG_LOGIN_HINTS, _CONFIG_LOGIN_WORDS) >= 0 and not _is_address_name(name)


def _key_secret(k, v, secret, entry):
    """Whether the value of k shows masked: under a secret name or below one. The id, name
    or label of a list entry stays in clear, so the entries can be told apart."""
    if entry and k in _CONFIG_ID_KEYS and isinstance(v, (str, int, float)):
        return False
    return secret or _is_secret_name(k)


def _mask_value(v):
    scheme = v.split('://', 1)[0] if '://' in v else ''
    return f'{scheme}://{_CONFIG_MASK}' if _CONFIG_SCHEME.match(scheme) else _CONFIG_MASK


def _conn_masked(v):
    """v with the value of each secret part masked (Password=, Pwd=, AccountKey=), None for
    a string without one. A value in braces or quotes may hold a ; of its own."""
    parts, hit, i = [], False, 0
    while True:
        eq, semi = v.find('=', i), v.find(';', i)
        if eq < 0 or 0 <= semi < eq:
            end = len(v) if semi < 0 else semi
            parts.append(v[i:end])
        else:
            j = eq + 1
            while j < len(v) and v[j] == ' ':
                j += 1
            if j < len(v) and v[j] in '{"\'':
                close = '}' if v[j] == '{' else v[j]
                j += 1
                while j < len(v) and not (v[j] == close and v[j + 1:j + 2] != close):
                    j += 2 if v[j] == close else 1
                j += 1
            end = v.find(';', min(j, len(v)))
            end = len(v) if end < 0 else end
            name = v[i:eq]
            if _CONFIG_CONN_KEY.match(name) and _is_secret_name(name.strip()) and v[eq + 1:end].strip():
                parts.append(f'{name}={_CONFIG_MASK}')
                hit = True
            else:
                parts.append(v[i:end])
        if end >= len(v):
            break
        i = end + 1
    return ';'.join(parts) if hit else None


def _login_masked(v):
    """v with the login it carries masked, the user and password of a url or the secret
    parts of a connection string, None for a value without one. Text without a ; is no
    connection string ("set key=foo to enable").

    MK Nov 2026 - database_url, a broker or redis url or an https_proxy with user:pw@
    went out in clear, as they stand under an address name. The host stays to read."""
    if not isinstance(v, str):
        return None
    m = _CONFIG_URL_LOGIN.match(v)
    if m:
        return f'{m.group(1)}{_CONFIG_MASK}@{v[m.end():]}'
    return _conn_masked(v) if '=' in v and ';' in v else None


def _masked_form(v, secret=True):
    """What a value shows as, None for one that shows as it is: any string or number under
    a secret name, and elsewhere the login a url or a connection string carries."""
    if not secret:
        return _login_masked(v)
    if isinstance(v, str):
        return _mask_value(v) if v else None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return _CONFIG_MASK
    return None


def _config_generation(plugin):
    return _CONFIG_GENERATION.setdefault(plugin, secrets.token_hex(8))


def _config_written(plugin):
    _CONFIG_GENERATION[plugin] = secrets.token_hex(8)


def _entry_fp(plugin, lpath, o, key):
    """The keyed print of an entry of the stored list at lpath of a plugin, until its
    config.json is written again."""
    msg = b'\x00'.join((b'plugin-config-entry', plugin.encode(), _config_generation(plugin).encode(),
                        lpath.encode(), json.dumps(o).encode()))
    return hmac.new(key, msg, hashlib.sha256).digest()[:8]


def _entry_pad(nonce, key):
    return hmac.new(key, b'plugin-config-pad\x00' + nonce, hashlib.sha256).digest()[:8]


def _entry_handle(plugin, lpath, o, key):
    """'#', a random nonce and the print of o under a pad of that nonce.

    MK Nov 2026 - an entry of a list was put back by its place, so deleting the first of
    two telegram urls kept the first and lost the second. Each masked entry carries a
    handle of its own now, and a save finds the stored entry by it wherever it sits. A
    handle holds in the list it was read from only, until the file is written again, and
    finds a stored entry of its value there, however many copies of it there are. Equal
    values never show the same handle."""
    nonce = secrets.token_bytes(8)
    pad = _entry_pad(nonce, key)
    return '#' + nonce.hex() + bytes(a ^ b for a, b in zip(_entry_fp(plugin, lpath, o, key), pad)).hex()


def _handle_fp(text, key):
    """(where the handle in text starts, the print it carries), (None, None) for none."""
    m = _CONFIG_HANDLE.search(text)
    if not m:
        return None, None
    nonce, blob = bytes.fromhex(m.group(1)), bytes.fromhex(m.group(2))
    return m.start(), bytes(a ^ b for a, b in zip(blob, _entry_pad(nonce, key)))


def _entry_key():
    try:
        return get_db().aes_key or _CONFIG_PROCESS_KEY
    except Exception:
        return _CONFIG_PROCESS_KEY


def _masked_config(obj, plugin='', key=None):
    """obj with every string and number under a secret-named key masked, at any depth."""
    key = _entry_key() if key is None else key

    def mask(obj, secret, path, entry=False):
        if isinstance(obj, dict):
            return {k: mask(v, _key_secret(k, v, secret, entry), _key_path(path, k)) for k, v in obj.items()}
        if isinstance(obj, list):
            out = []
            for i, x in enumerate(obj):
                form = _masked_form(x, secret)
                out.append(form + _entry_handle(plugin, path, x, key) if form else mask(x, secret, f'{path}[{i}]', True))
            return out
        form = _masked_form(obj, secret)
        return obj if form is None else form

    return mask(obj, False, '')


def _has_mask(obj):
    if isinstance(obj, dict):
        return any(_has_mask(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_mask(x) for x in obj)
    return isinstance(obj, str) and _CONFIG_MASK in obj


def _shown_as_is(obj, secret=False, entry=False):
    """The strings of obj that the editor shows as they are stored."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _shown_as_is(v, _key_secret(k, v, secret, entry))
    elif isinstance(obj, list):
        for x in obj:
            yield from _shown_as_is(x, secret, True)
    elif isinstance(obj, str) and not secret and _login_masked(obj) is None:
        yield obj


def _is_address(k, v, secret=False):
    """Whether the value v of k is an address: one under an address name, but a flag never,
    a number only as a port (show_ip_addresses, url_timeout) and a label or a mode only as a
    url (server_label, proxy_mode), and a url with a host under any plain name (issuer,
    target, instance)."""
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return bool(_CONFIG_PORT_WORD.search(_config_name(k)))
    if _is_address_name(k):
        if isinstance(v, str) and not _CONFIG_URL.match(v):
            n = _config_name(k)
            return not _CONFIG_NOT_ADDRESS.search(n, _hint_at(n, _CONFIG_ADDRESS_HINTS, _CONFIG_ADDRESS_WORDS))
        return True
    return isinstance(v, str) and not secret and not _is_secret_name(k) and bool(_CONFIG_URL.match(v))


def _address_values(obj, path=''):
    """The addresses in obj and in the objects below it, by path. A list entry is held to
    its own, the lists are left to _list_addresses."""
    out = {}
    for k, v in obj.items():
        here = _key_path(path, k)
        if _is_address(k, v):
            out[here] = json.dumps(v, sort_keys=True)
        elif isinstance(v, dict):
            out.update(_address_values(v, here))
    return out


def _list_addresses(obj, path='', inside=False, secret=False):
    """The addresses the lists in obj hold, as sets by their path without places: a value
    under an address name in a list entry, or an entry that is a url with a host."""
    out = {}

    def add(found):
        for p, vals in found.items():
            out.setdefault(p, set()).update(vals)

    if isinstance(obj, dict):
        for k, v in obj.items():
            here = _key_path(path, k)
            if inside and _is_address(k, v, secret):
                add({here: {json.dumps(v, sort_keys=True)}})
            elif isinstance(v, (dict, list)):
                add(_list_addresses(v, here, inside, secret or _is_secret_name(k)))
    elif isinstance(obj, list):
        for x in obj:
            # an apprise url under a secret name is the secret itself
            if not secret and isinstance(x, str) and _CONFIG_URL.match(x):
                add({f'{path}[]': {json.dumps(x)}})
            elif isinstance(x, (dict, list)):
                add(_list_addresses(x, f'{path}[]', True, secret))
    return out


def _stored_entry(x, i, new, items):
    """(stored path, value) of the stored dict or list that a dict or list inside a list
    stands for, the entries of every stored list for a list among lists, or None."""
    olds = [o for _, _, o in items]

    def at(n):
        lp, j, o = items[n]
        return f'{lp}[{j}]', o

    if isinstance(x, dict):
        for k in _CONFIG_ID_KEYS:
            v = x.get(k)
            if isinstance(v, (str, int)) and _CONFIG_MASK not in str(v):
                hits = [n for n, o in enumerate(olds)
                        if isinstance(o, dict) and type(o.get(k)) is type(v) and o.get(k) == v]
                if len(hits) == 1:
                    return at(hits[0])
                # two of that name go by their place, while no entry came or went
                if i in hits and len(new) == len(olds):
                    return at(i)
                return None
    # by its place only while no entry came or went
    if len(new) == len(olds) and type(olds[i]) is type(x):
        return at(i)
    if isinstance(x, list):
        return [(f'{lp}[{j}]', n, y) for lp, j, o in items if isinstance(o, list) for n, y in enumerate(o)]
    return None


def _unmasked_config(new, stored, plugin='', key=None):
    """new with each masked value put back to the stored one it stands for.

    Raises _CredentialRequired with the places of masks that stand for nothing stored:
    a handle no entry of the stored list it was read from has, a mask from an editor
    opened before the value changed, or masked values in a list entry that matches no
    stored one. And with the secrets kept masked in an object whose addresses the same
    save changed."""
    key = _entry_key() if key is None else key
    literal = {s for s in _shown_as_is(stored) if _CONFIG_MASK in s}
    # kept: (place, how many lists deep its object sits) of each secret kept masked, where
    # a list entry belongs to the object that holds the list
    left, kept = [], []
    tables = {}    # the prints of each stored list by its path, each list gone through once

    def walk(new, old, spath, secret, path, entry=False, depth=0, addr=False, owner=None):
        # spath is where old sits in the stored file, path where new sits in the save
        if isinstance(new, dict):
            old = old if isinstance(old, dict) else {}
            start = len(kept)
            out = {k: walk(v, old.get(k), _key_path(spath, k), _key_secret(k, v, secret, entry), _key_path(path, k),
                           depth=depth, addr=_is_address_name(k))
                   for k, v in new.items()}
            if len(kept) > start:
                now, before = _address_values(out), _address_values(old)
                moved = sorted(p for p in set(now) | set(before) if now.get(p) != before.get(p))
                fields = [p for p, _ in kept[start:]] if moved else []
                # a secret of this object outside its lists goes to the addresses in them too:
                # one that is new there moves it
                outside = [p for p, n in kept[start:] if n == depth]
                if outside:
                    held, had = _list_addresses(out), _list_addresses(old)
                    added = sorted(p for p, vals in held.items() if vals - had.get(p, set()))
                    moved, fields = moved + added, fields or (outside if added else [])
                if moved:
                    raise _CredentialRequired(fields, [_key_path(path, p) for p in moved])
            return out
        if isinstance(new, list):
            items = [(spath, j, o) for j, o in enumerate(old)] if isinstance(old, list) else []
            return walk_list(new, items, secret, path, depth + 1, addr, depth if owner is None else owner)
        if isinstance(new, str) and _CONFIG_MASK in new:
            form = _masked_form(old, secret)
            if form is not None and form == new:
                # one under an address name is an address itself, the check above compares it,
                # and a url carries the host its login is for
                if not addr and (secret or '://' not in old):
                    kept.append((path or '(top level)', depth))
                return old
            # a string the editor shows as it is stored may hold the mask itself, and one
            # typed into a plain field without a login stands for nothing that could be lost
            if secret or (new not in literal and _login_masked(new) is not None):
                left.append(path or '(top level)')
        return new

    def stored_by_print(fp, items, lists, secret):
        todo = {lp for lp in lists if (lp, secret) not in tables}
        if todo:
            for lp in todo:
                tables[lp, secret] = {}
            for lp, _, y in items:
                if lp in todo and _masked_form(y, secret) is not None:
                    tables[lp, secret][_entry_fp(plugin, lp, y, key)] = y
        return next((tables[lp, secret][fp] for lp in lists if fp in tables[lp, secret]), None)

    def walk_list(new, items, secret, path, depth, addr, owner):
        # items holds (path of the stored list, place, value) for each stored entry new may stand for
        lists, out = None, []
        for i, x in enumerate(new):
            here = f'{path}[{i}]'
            if not _has_mask(x):
                out.append(x)
            elif isinstance(x, str):
                # the stored entry of this list with the value of the handle, wherever it sits now
                at, fp = _handle_fp(x, key)
                o = None
                if fp is not None:
                    lists = lists if lists is not None else list(dict.fromkeys(lp for lp, _, _ in items))
                    o = stored_by_print(fp, items, lists, secret)
                if o is None or _masked_form(o, secret) != x[:at]:
                    out.append(walk(x, None, '', secret, here, depth=depth))
                    continue
                # a url carries its own address, as does any entry of a list under an address name
                if not addr and '://' not in x[:at]:
                    kept.append((here, owner))
                out.append(o)
            else:
                hit, start = _stored_entry(x, i, new, items), len(kept)
                if isinstance(hit, list):
                    v = walk_list(x, hit, secret, here, depth + 1, addr, owner)
                else:
                    spath, o = hit or ('', None)
                    v = walk(x, o, spath, secret, here, True, depth, addr, owner)
                # an entry without an address of its own (a login, a key with a name) belongs
                # to the object that holds the list, as a string entry does
                if len(kept) > start and isinstance(v, dict) and not _list_addresses(v, '', True, secret):
                    kept[start:] = [(p, owner) for p, _ in kept[start:]]
                out.append(v)
        return out

    out = walk(new, stored, '', False, '')
    if left:
        raise _CredentialRequired(left)
    return out


# a folder PegaProx cannot write to: the save says so, config.json stays as it was
_CONFIG_NOT_WRITABLE = (errno.EACCES, errno.EPERM, errno.EROFS)


def _config_not_writable(e):
    """The answer for a config.json that could not be written because of its folder, or None."""
    if not isinstance(e, OSError):
        return None
    if e.errno in _CONFIG_NOT_WRITABLE:
        return 'PegaProx cannot write to the plugin folder, config.json was not changed'
    if e.errno == errno.EBUSY:
        # a config.json mounted as a file of its own: no new file can take its place
        return ('config.json is mounted as a single file and cannot be replaced, mount the plugin '
                'folder instead; config.json was not changed')
    return None


def _write_config(path, raw):
    """Write a plugin's config.json, secrets and all. The text goes to a new file beside
    it, created 0600, which then takes its place: the file ends 0600 and the service's,
    whoever owned the old one, where a chmod of that one fails. An error leaves the old
    file as it was."""
    path = str(path)
    tmp = os.path.join(os.path.dirname(path), f'.config.json.{secrets.token_hex(6)}.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@bp.route('/api/plugins/<plugin_id>/config', methods=['GET'])
@require_auth(perms=['plugins.manage'])
def get_plugin_config(plugin_id):
    """Read plugin config.json as raw text"""
    if not _valid_plugin_id(plugin_id):
        return jsonify({'error': 'Invalid plugin id'}), 400
    config_path = _safe_plugin_path(plugin_id)
    if not config_path:
        return jsonify({'error': 'Invalid plugin ID'}), 400
    if not config_path.exists():
        return jsonify({'error': 'No config.json found for this plugin'}), 404
    try:
        raw = config_path.read_text(encoding='utf-8')
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500
    try:
        raw = json.dumps(_masked_config(json.loads(raw), plugin_id), indent=4)
    except ValueError:
        # a file that does not parse can hold a credential in any shape; the editor
        # starts from an empty object and a save writes a new file
        raw = ''
    return jsonify({'config': raw})


@bp.route('/api/plugins/<plugin_id>/config', methods=['PUT'])
@require_auth(perms=['plugins.manage'])
def save_plugin_config(plugin_id):
    """Write plugin config.json — validates JSON before saving"""
    if not _valid_plugin_id(plugin_id):
        return jsonify({'error': 'Invalid plugin id'}), 400
    config_path = _safe_plugin_path(plugin_id)
    if not config_path:
        return jsonify({'error': 'Invalid plugin ID'}), 400
    if not config_path.parent.exists():
        return jsonify({'error': 'Plugin not found'}), 404

    data = request.get_json() or {}
    raw = data.get('config', '')
    if not raw:
        return jsonify({'error': 'Empty config'}), 400

    # validate JSON
    try:
        new_cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON: {e}'}), 400
    except RecursionError:
        return jsonify({'error': 'The config is nested too deeply'}), 400

    stored, have_stored = {}, False
    try:
        if config_path.exists():
            stored, have_stored = json.loads(config_path.read_text(encoding='utf-8')), True
    except (OSError, ValueError):
        pass    # a file that does not parse is written anew
    if _CONFIG_MASK in json.dumps(new_cfg):
        try:
            new_cfg = _unmasked_config(new_cfg, stored, plugin_id)
        except RecursionError:
            return jsonify({'error': 'The config is nested too deeply'}), 400
        except _CredentialRequired as e:
            if e.moved:
                msg = f"Re-enter {', '.join(e.fields)} to change {', '.join(e.moved)}."
            else:
                # whatever stands for no stored value is never written as one, nor dropped
                msg = (f"Type the value of {', '.join(e.fields)} instead of {_CONFIG_MASK}, or reload "
                       "the editor: the masked value stands for nothing stored.")
            return jsonify({'error': msg, 'code': 'CREDENTIAL_REQUIRED', 'fields': e.fields}), 400
        raw = json.dumps(new_cfg, indent=4)

    # MK Nov 2026 - the editor shows the file masked and indented its own way, so saving
    # what it showed rewrote the whole file although no value changed. Such a save leaves
    # config.json as it is, and the handles read before it still hold.
    if have_stored and json.dumps(new_cfg) == json.dumps(stored):
        try:
            os.chmod(config_path, 0o600)
        except OSError:
            # a file of another owner: the same text goes into one of the service's own,
            # and the handles still hold, as nothing in it changed
            try:
                if stat.S_IMODE(os.stat(config_path).st_mode) & 0o077:
                    _write_config(config_path, config_path.read_text(encoding='utf-8'))
            except OSError as e:
                logging.warning(f"[PLUGINS] config.json of {plugin_id} keeps its mode: {e}")
    else:
        try:
            _write_config(config_path, raw)
            _config_written(plugin_id)
        except Exception as e:
            msg = _config_not_writable(e)
            if msg:
                logging.warning(f"[PLUGINS] config.json of {plugin_id} not saved: {e}")
                return jsonify({'error': msg}), 500
            return jsonify({'error': safe_error(e, 'Failed to write config')}), 500

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'plugins.config_saved', f"Updated config for plugin: {plugin_id}")

    return jsonify({'success': True})
