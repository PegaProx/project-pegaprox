# -*- coding: utf-8 -*-
"""
PegaProx Plugin Management API - Layer 6
NS: Mar 2026 - auto-discover plugins from plugins/ dir, enable/disable via Settings

Plugins register route handlers via register_plugin_route() which are dispatched
through a single catch-all Flask route. This avoids Flask's restriction on
registering blueprints after the first request — plugins can be loaded at runtime.
"""

import json
import sys
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

bp = Blueprint('plugins', __name__)

# in-memory registries
_loaded_plugins = {}   # {plugin_id: module}
_plugin_routes = {}    # {plugin_id: {path: handler_fn}}


# ---- Plugin Route Registration (used by plugins) ----

def register_plugin_route(plugin_id, path, handler):
    """Register a route handler for a plugin. Called from plugin's register() function.

    Usage in plugin __init__.py:
        from pegaprox.api.plugins import register_plugin_route
        def register(app):
            register_plugin_route('my_plugin', 'status', my_handler)
    """
    _plugin_routes.setdefault(plugin_id, {})[path] = handler


# ---- Catch-all route for plugin API calls ----

@bp.route('/api/plugins/<plugin_id>/api/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@require_auth(perms=['plugins.view'])
def plugin_proxy(plugin_id, subpath):
    """Dispatch API requests to loaded plugins"""
    if plugin_id not in _loaded_plugins:
        return jsonify({'error': 'Plugin not loaded'}), 404

    routes = _plugin_routes.get(plugin_id, {})
    handler = routes.get(subpath)
    if not handler:
        return jsonify({'error': f'Route not found: {subpath}'}), 404

    try:
        result = handler()
        if isinstance(result, dict) or isinstance(result, list):
            return jsonify(result)
        return result
    except Exception as e:
        logging.error(f"[PLUGINS] {plugin_id}/{subpath} error: {e}")
        return jsonify({'error': str(e)}), 500


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
    """Load a plugin module and call its register() function"""
    plugin_dir = Path(PLUGINS_DIR) / plugin_id
    init_file = plugin_dir / '__init__.py'

    if not init_file.exists():
        return False, 'No __init__.py found'

    try:
        mod_name = f'plugins.{plugin_id}'
        spec = importlib.util.spec_from_file_location(mod_name, init_file)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)

        # plugin calls register_plugin_route() inside register()
        if hasattr(mod, 'register'):
            mod.register(app)

        _loaded_plugins[plugin_id] = mod
        logging.info(f"[PLUGINS] Loaded: {plugin_id}")
        return True, ''

    except Exception as e:
        logging.error(f"[PLUGINS] Failed to load {plugin_id}: {e}")
        if f'plugins.{plugin_id}' in sys.modules:
            del sys.modules[f'plugins.{plugin_id}']
        return False, str(e)


def unload_plugin(plugin_id):
    """Unload a plugin — remove routes and module"""
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
            else:
                _set_plugin_state(pid, True, error=err)

    if loaded:
        logging.info(f"[PLUGINS] {len(loaded)} plugin(s) loaded: {', '.join(loaded)}")


def start_plugin_backgrounds():
    for pid, mod in _loaded_plugins.items():
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
    for plugin in discovered:
        pid = plugin['_id']
        state = states.get(pid, {})
        # get registered routes for this plugin
        routes = list(_plugin_routes.get(pid, {}).keys())
        result.append({
            'id': pid,
            'name': plugin.get('name', pid),
            'version': plugin.get('version', ''),
            'author': plugin.get('author', ''),
            'description': plugin.get('description', ''),
            'enabled': bool(state.get('enabled', 0)),
            'loaded': pid in _loaded_plugins,
            'error': state.get('error', '') or plugin.get('error', ''),
            'has_init': plugin.get('_has_init', False),
            'routes': routes,
        })

    return jsonify(result)


@bp.route('/api/plugins/<plugin_id>/enable', methods=['POST'])
@require_auth(perms=['plugins.manage'])
def enable_plugin(plugin_id):
    """Enable and load a plugin at runtime"""
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
