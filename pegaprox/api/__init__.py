# -*- coding: utf-8 -*-
"""
PegaProx API Blueprint Registration
"""
import importlib.util


_REQUIRED_BLUEPRINT_MODULES = [
    "pegaprox.api.auth",
    "pegaprox.api.users",
    "pegaprox.api.clusters",
    "pegaprox.api.vms",
    "pegaprox.api.nodes",
    "pegaprox.api.pbs",
    "pegaprox.api.storage",
    "pegaprox.api.datacenter",
    "pegaprox.api.vmware",
    "pegaprox.api.schedules",
    "pegaprox.api.reports",
    "pegaprox.api.settings",
    "pegaprox.api.alerts",
    "pegaprox.api.realtime",
    "pegaprox.api.search",
    "pegaprox.api.static_files",
    "pegaprox.api.history",
    "pegaprox.api.groups",
    "pegaprox.api.ceph",
]


def validate_blueprint_modules(spec_resolver=None):
    """Return list of missing required API blueprint modules."""
    resolver = spec_resolver or importlib.util.find_spec
    missing = []
    for module_name in _REQUIRED_BLUEPRINT_MODULES:
        if resolver(module_name) is None:
            missing.append(module_name)
    return missing


def register_blueprints(app):
    """Register all API blueprints with the Flask app."""
    missing_modules = validate_blueprint_modules()
    if missing_modules:
        missing_text = ", ".join(missing_modules)
        raise RuntimeError(
            "Startup integrity check failed: missing API module(s): "
            f"{missing_text}. This usually means an incomplete/mixed update. "
            "Re-run ./update.sh --force and restart pegaprox."
        )

    from pegaprox.api.auth import bp as auth_bp
    from pegaprox.api.users import bp as users_bp
    from pegaprox.api.clusters import bp as clusters_bp
    from pegaprox.api.vms import bp as vms_bp
    from pegaprox.api.nodes import bp as nodes_bp
    from pegaprox.api.pbs import bp as pbs_bp
    from pegaprox.api.storage import bp as storage_bp
    from pegaprox.api.datacenter import bp as datacenter_bp
    from pegaprox.api.vmware import bp as vmware_bp
    from pegaprox.api.schedules import bp as schedules_bp
    from pegaprox.api.reports import bp as reports_bp
    from pegaprox.api.settings import bp as settings_bp
    from pegaprox.api.alerts import bp as alerts_bp
    from pegaprox.api.realtime import bp as realtime_bp
    from pegaprox.api.search import bp as search_bp
    from pegaprox.api.static_files import bp as static_files_bp
    from pegaprox.api.history import bp as history_bp
    from pegaprox.api.groups import bp as groups_bp
    from pegaprox.api.ceph import bp as ceph_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(clusters_bp)
    app.register_blueprint(vms_bp)
    app.register_blueprint(nodes_bp)
    app.register_blueprint(pbs_bp)
    app.register_blueprint(storage_bp)
    app.register_blueprint(datacenter_bp)
    app.register_blueprint(vmware_bp)
    app.register_blueprint(schedules_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(realtime_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(static_files_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(groups_bp)
    app.register_blueprint(ceph_bp)

    # Initialize WebSocket support for realtime blueprint
    from pegaprox.api.realtime import sock
    sock.init_app(app)
