# -*- coding: utf-8 -*-
"""
PegaProx Plugin Management API - Layer 6
NS: Mar 2026 - auto-discover plugins from plugins/ dir, enable/disable via Settings

Plugins register route handlers via register_plugin_route() which are dispatched
through a single catch-all Flask route. This avoids Flask's restriction on
registering blueprints after the first request — plugins can be loaded at runtime.
"""

import json
import re
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


def _get_plugin_states():
    db = get_db()
    rows = db.query('SELECT plugin_id, enabled, loaded_at, error FROM plugin_state') or []
    return {r['plugin_id']: dict(r) for r in rows}


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


def load_enabled_plugins(app):
    """Called once at startup — load all enabled plugins"""
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


def start_plugin_backgrounds():
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
        return jsonify({'error': f'Failed to delete plugin files: {e}'}), 500

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'plugins.deleted', f"Deleted plugin: {plugin_id}")

    return jsonify({'success': True, 'message': f'Plugin {plugin_id} deleted.'})


def _safe_plugin_path(plugin_id, filename='config.json'):
    """Validate plugin_id and return safe path — prevents path traversal"""
    if '..' in plugin_id or '/' in plugin_id or '\\' in plugin_id:
        return None
    resolved = (Path(PLUGINS_DIR) / plugin_id / filename).resolve()
    if not str(resolved).startswith(str(Path(PLUGINS_DIR).resolve())):
        return None
    return resolved


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
        return jsonify({'config': config_path.read_text(encoding='utf-8')})
    except Exception as e:
        return jsonify({'error': safe_error(e)}), 500


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
        json.loads(raw)
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON: {e}'}), 400

    try:
        config_path.write_text(raw, encoding='utf-8')
    except Exception as e:
        return jsonify({'error': f'Failed to write: {e}'}), 500

    usr = getattr(request, 'session', {}).get('user', 'system')
    log_audit(usr, 'plugins.config_saved', f"Updated config for plugin: {plugin_id}")

    return jsonify({'success': True})
