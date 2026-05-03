# -*- coding: utf-8 -*-
"""
PegaProx API Blueprint Registration
"""
import logging


def register_blueprints(app):
    """Register all API blueprints with the Flask app."""
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
    from pegaprox.api.xhm import bp as xhm_bp
    from pegaprox.api.site_recovery import bp as site_recovery_bp
    from pegaprox.api.plugins import bp as plugins_bp
    from pegaprox.api.webauthn import bp as webauthn_bp
    from pegaprox.api.metrics_exporter import bp as metrics_exporter_bp
    from pegaprox.api.insights import bp as insights_bp
    from pegaprox.api.templates_lib import bp as templates_lib_bp
    from pegaprox.api.push import bp as push_bp, register_alert_handler
    from pegaprox.api.costs import bp as costs_bp
    from pegaprox.api.drift import bp as drift_bp, start_scanner as start_drift_scanner
    from pegaprox.api.audit_search import bp as audit_search_bp
    from pegaprox.api.siem import bp as siem_bp, start_worker as start_siem_worker
    from pegaprox.api.snapshots import bp as snapshots_bp, start_scheduler as start_snap_scheduler
    from pegaprox.api.topology import bp as topology_bp
    from pegaprox.api.power import bp as power_bp
    from pegaprox.api.dr_drill import bp as dr_drill_bp

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
    app.register_blueprint(xhm_bp)
    app.register_blueprint(site_recovery_bp)
    app.register_blueprint(plugins_bp)
    app.register_blueprint(webauthn_bp)
    app.register_blueprint(metrics_exporter_bp)
    app.register_blueprint(insights_bp)
    app.register_blueprint(templates_lib_bp)
    app.register_blueprint(push_bp)
    app.register_blueprint(costs_bp)
    app.register_blueprint(drift_bp)
    app.register_blueprint(audit_search_bp)
    app.register_blueprint(siem_bp)
    app.register_blueprint(snapshots_bp)
    app.register_blueprint(topology_bp)
    app.register_blueprint(power_bp)
    app.register_blueprint(dr_drill_bp)

    # Initialize WebSocket support for realtime blueprint
    from pegaprox.api.realtime import sock
    sock.init_app(app)

    # MK May 2026 — wire push handler into the alerts pipeline
    try:
        register_alert_handler()
    except Exception:
        pass

    # NS May 2026 — drift scanner thread (6h cadence; harmless if mgrs not yet up)
    try:
        start_drift_scanner()
    except Exception as e:
        logging.warning(f"drift scanner start failed: {e}")

    # MK May 2026 — SIEM forwarder worker
    try:
        start_siem_worker()
    except Exception as e:
        logging.warning(f"siem worker start failed: {e}")

    # NS May 2026 — snapshot scheduler (60s tick, idempotent)
    try:
        start_snap_scheduler()
    except Exception as e:
        logging.warning(f"snapshot scheduler start failed: {e}")
