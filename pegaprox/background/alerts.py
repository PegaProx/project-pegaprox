# -*- coding: utf-8 -*-
"""
PegaProx Alert Monitoring - Layer 7
Background alert checking and notification.
"""

import os
import time
import json
import logging
import threading
import uuid
from datetime import datetime

from pegaprox.constants import ALERTS_CONFIG_FILE
from pegaprox.globals import (
    cluster_managers, _alert_running, _alert_last_sent, _alert_thread,
)
from pegaprox.core.db import get_db
from pegaprox.api.helpers import load_server_settings
from pegaprox.utils.email import send_email

def load_alerts_config():
    """Load alerts configuration from SQLite database
    
    SQLite migration
    """
    defaults = {'alerts': [], 'enabled': True}
    
    try:
        db = get_db()
        alerts = db.get_all_alerts()
        
        if alerts:
            # Convert alerts dict to list format expected by the rest of the code
            alert_list = list(alerts.values())
            return {'alerts': alert_list, 'enabled': True}
    except Exception as e:
        logging.error(f"Error loading alerts from database: {e}")
        # Legacy fallback
        if os.path.exists(ALERTS_CONFIG_FILE):
            try:
                with open(ALERTS_CONFIG_FILE, 'r') as f:
                    return {**defaults, **json.load(f)}
            except:
                pass
    
    return defaults


def save_alerts_config(config):
    """Save alerts configuration to SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        
        # Convert alerts list to dict format for database
        alerts_dict = {}
        for alert in config.get('alerts', []):
            alert_id = alert.get('id', str(uuid.uuid4())[:8])
            alerts_dict[alert_id] = alert
        
        db.save_all_alerts(alerts_dict)
        return True
    except Exception as e:
        logging.error(f"Error saving alerts config: {e}")
        return False

def check_and_send_alerts():
    """Check all alert conditions and send notifications
    
    LW: This runs periodically in a background thread
    Checks CPU, RAM, Disk usage against thresholds
    """
    config = load_alerts_config()
    if not config.get('enabled'):
        return
    
    settings = load_server_settings()
    recipients = settings.get('alert_email_recipients', [])
    cooldown = settings.get('alert_cooldown', 300)
    
    if not recipients:
        return
    
    current_time = time.time()
    
    for alert in config.get('alerts', []):
        if not alert.get('enabled', True):
            continue
        
        alert_id = alert.get('id', '')
        cluster_id = alert.get('cluster_id', '')
        metric = alert.get('metric', '')  # cpu, memory, disk
        threshold = alert.get('threshold', 80)
        operator = alert.get('operator', '>')  # >, <, =
        target_type = alert.get('target_type', 'cluster')  # cluster, node, vm
        target_id = alert.get('target_id', '')  # node name or vmid
        
        # Check cooldown
        alert_key = f"{cluster_id}:{target_type}:{target_id}:{metric}"
        if alert_key in _alert_last_sent:
            if current_time - _alert_last_sent[alert_key] < cooldown:
                continue
        
        # Get current value
        current_value = None
        target_name = target_id
        
        if cluster_id in cluster_managers:
            manager = cluster_managers[cluster_id]
            
            if target_type == 'cluster':
                # Get cluster-wide metrics
                summary = manager.get_cluster_summary()
                if metric == 'cpu':
                    current_value = summary.get('cpu_usage', 0)
                elif metric == 'memory':
                    mem = summary.get('memory', {})
                    if mem.get('total', 0) > 0:
                        current_value = (mem.get('used', 0) / mem.get('total', 1)) * 100
                elif metric == 'disk':
                    storage = summary.get('storage', {})
                    if storage.get('total', 0) > 0:
                        current_value = (storage.get('used', 0) / storage.get('total', 1)) * 100
                target_name = manager.config.name
                
            elif target_type == 'node':
                node_summary = manager.get_node_summary(target_id)
                if metric == 'cpu':
                    current_value = node_summary.get('cpu', 0) * 100
                elif metric == 'memory':
                    mem = node_summary.get('memory', {})
                    if mem.get('total', 0) > 0:
                        current_value = (mem.get('used', 0) / mem.get('total', 1)) * 100
                elif metric == 'disk':
                    rootfs = node_summary.get('rootfs', {})
                    if rootfs.get('total', 0) > 0:
                        current_value = (rootfs.get('used', 0) / rootfs.get('total', 1)) * 100
                        
            elif target_type == 'vm':
                # Get VM metrics
                for res in manager.get_resources():
                    if str(res.get('vmid')) == str(target_id):
                        if metric == 'cpu':
                            current_value = res.get('cpu', 0) * 100
                        elif metric == 'memory':
                            if res.get('maxmem', 0) > 0:
                                current_value = (res.get('mem', 0) / res.get('maxmem', 1)) * 100
                        elif metric == 'disk':
                            if res.get('maxdisk', 0) > 0:
                                current_value = (res.get('disk', 0) / res.get('maxdisk', 1)) * 100
                        target_name = res.get('name', target_id)
                        break
        
        if current_value is None:
            continue
        
        # Check condition
        triggered = False
        if operator == '>' and current_value > threshold:
            triggered = True
        elif operator == '<' and current_value < threshold:
            triggered = True
        elif operator == '>=' and current_value >= threshold:
            triggered = True
        elif operator == '<=' and current_value <= threshold:
            triggered = True
        
        if triggered:
            # Send alert
            alert_name = alert.get('name', f'{metric} Alert')
            subject = f"[PegaProx Alert] {alert_name}"
            body = f"""
Alert: {alert_name}
Target: {target_type.capitalize()} - {target_name}
Metric: {metric.upper()}
Condition: {metric} {operator} {threshold}%
Current Value: {current_value:.1f}%
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Cluster: {cluster_id}

This is an automated alert from PegaProx.
"""
            html_body = f"""
<h2 style="color: #e74c3c;">⚠️ PegaProx Alert: {alert_name}</h2>
<table style="border-collapse: collapse; width: 100%; max-width: 500px;">
<tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Target</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{target_type.capitalize()} - {target_name}</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Metric</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{metric.upper()}</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Condition</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{metric} {operator} {threshold}%</td></tr>
<tr style="background-color: #fee2e2;"><td style="padding: 8px; border: 1px solid #ddd;"><strong>Current Value</strong></td><td style="padding: 8px; border: 1px solid #ddd;"><strong>{current_value:.1f}%</strong></td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Time</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
</table>
<p style="color: #666; font-size: 12px; margin-top: 20px;">This is an automated alert from PegaProx.</p>
"""
            
            success, error = send_email(recipients, subject, body, html_body)
            if success:
                _alert_last_sent[alert_key] = current_time
                logging.info(f"Alert sent: {alert_name} ({metric}={current_value:.1f}%)")
            elif error:
                logging.warning(f"Alert email failed: {error}")


# Alert check thread
_alert_thread = None
_alert_running = False

def alert_check_loop():
    """Background thread that checks alerts periodically"""
    global _alert_running
    _alert_running = True
    
    while _alert_running:
        try:
            check_and_send_alerts()
        except Exception as e:
            logging.error(f"Alert check error: {e}")
        
        # Check every 60 seconds
        time.sleep(60)

def start_alert_thread():
    global _alert_thread
    if _alert_thread is None or not _alert_thread.is_alive():
        _alert_thread = threading.Thread(target=alert_check_loop, daemon=True)
        _alert_thread.start()
        logging.info("Alert monitoring thread started")



