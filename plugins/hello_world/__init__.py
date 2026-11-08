"""
Hello World Plugin - Example plugin for PegaProx
Demonstrates how to build a plugin with routes, auth, and PegaProx API access.

All plugin routes are automatically protected by authentication (plugins.view permission).
Plugins can access PegaProx internals: cluster_managers, get_db(), request, etc.
"""
import logging
from flask import request
from pegaprox.api.plugins import register_plugin_route
from pegaprox.globals import cluster_managers
from pegaprox.core.db import get_db

PLUGIN_NAME = "Hello World"


def _get_status():
    """Example route: returns plugin status + connected cluster count"""
    # access cluster managers (same API as core PegaProx)
    connected = sum(1 for m in cluster_managers.values() if m.is_connected)
    total = len(cluster_managers)

    # access request context (user info from auth)
    user = getattr(request, 'session', {}).get('user', 'unknown')

    return {
        'plugin': 'hello_world',
        'status': 'running',
        'message': 'Hello from the plugin system!',
        'authenticated_user': user,
        'clusters': {'connected': connected, 'total': total}
    }


def _get_info():
    """Example route: returns plugin metadata"""
    return {
        'name': PLUGIN_NAME,
        'version': '1.0.0',
        'author': 'PegaProx Team',
        'description': 'Example plugin demonstrating the PegaProx plugin API',
        'available_routes': ['status', 'info'],
        'api_docs': {
            'status': 'GET /api/plugins/hello_world/api/status — Plugin status + cluster info',
            'info': 'GET /api/plugins/hello_world/api/info — Plugin metadata'
        }
    }


def register(app):
    """Called by PegaProx when the plugin is enabled.
    Use register_plugin_route(plugin_id, path, handler) to add API routes.
    All routes are auto-prefixed: /api/plugins/{plugin_id}/api/{path}
    Authentication is handled automatically (plugins.view permission required).
    """
    register_plugin_route('hello_world', 'status', _get_status)
    register_plugin_route('hello_world', 'info', _get_info)

    logging.info("[PLUGINS] Hello World plugin registered")
