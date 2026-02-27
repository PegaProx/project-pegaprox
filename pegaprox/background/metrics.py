# -*- coding: utf-8 -*-
"""
PegaProx Metrics Collection - Layer 7
Background metrics snapshot collection.
"""

import os
import time
import json
import logging
import threading
from datetime import datetime

from pegaprox.constants import CONFIG_DIR
METRICS_HISTORY_FILE = os.path.join(CONFIG_DIR, 'metrics_history.json')

from pegaprox.globals import cluster_managers
from pegaprox.core.db import get_db

def load_metrics_history():
    """Load historical metrics from SQLite database
    
    SQLite migration
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM metrics_history ORDER BY timestamp DESC LIMIT 1000')
        
        snapshots = []
        for row in cursor.fetchall():
            try:
                data = json.loads(row['data'])
                data['timestamp'] = row['timestamp']
                snapshots.append(data)
            except:
                pass
        
        return {'snapshots': snapshots, 'last_cleanup': None}
    except Exception as e:
        logging.error(f"Error loading metrics history from database: {e}")
        # Legacy fallback
        try:
            if os.path.exists(METRICS_HISTORY_FILE):
                with open(METRICS_HISTORY_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
    return {'snapshots': [], 'last_cleanup': None}


def save_metrics_history(history):
    """Save metrics history - now saves individual snapshots
    
    SQLite migration
    This function is kept for backwards compatibility
    """
    # In SQLite version, snapshots are saved individually
    pass


def save_metrics_snapshot(snapshot):
    """Save a single metrics snapshot to SQLite
    
    new SQLite function
    """
    try:
        db = get_db()
        cursor = db.conn.cursor()
        
        timestamp = snapshot.get('timestamp', datetime.now().isoformat())
        data = json.dumps({k: v for k, v in snapshot.items() if k != 'timestamp'})
        
        cursor.execute('''
            INSERT INTO metrics_history (timestamp, data)
            VALUES (?, ?)
        ''', (timestamp, data))
        
        # Cleanup old entries (keep last 1000)
        cursor.execute('''
            DELETE FROM metrics_history 
            WHERE id NOT IN (
                SELECT id FROM metrics_history 
                ORDER BY timestamp DESC LIMIT 1000
            )
        ''')
        
        db.conn.commit()
    except Exception as e:
        logging.error(f"Error saving metrics snapshot: {e}")


def collect_metrics_snapshot():
    """Collect current metrics from all clusters
    
    Called periodically to build historical data
    """
    snapshot = {
        'timestamp': datetime.now().isoformat(),
        'clusters': {}
    }
    
    for cluster_id, mgr in cluster_managers.items():
        if not mgr.is_connected:
            continue
        
        try:
            cluster_data = {
                'name': mgr.config.name,
                'nodes': {},
                'totals': {
                    'vms_running': 0,
                    'vms_stopped': 0,
                    'cts_running': 0,
                    'cts_stopped': 0,
                    'cpu_used': 0,
                    'cpu_total': 0,
                    'mem_used': 0,
                    'mem_total': 0
                }
            }
            
            # Collect node metrics
            for node_name, node_data in (mgr.nodes or {}).items():
                if node_data.get('status') != 'online':
                    continue
                
                cluster_data['nodes'][node_name] = {
                    'cpu': round(node_data.get('cpu', 0) * 100, 1),
                    'mem_percent': round(node_data.get('mem', 0) / max(node_data.get('maxmem', 1), 1) * 100, 1),
                    'maxcpu': node_data.get('maxcpu', 0),
                    'maxmem': node_data.get('maxmem', 0)
                }
                
                cluster_data['totals']['cpu_total'] += node_data.get('maxcpu', 0)
                cluster_data['totals']['cpu_used'] += node_data.get('cpu', 0) * node_data.get('maxcpu', 0)
                cluster_data['totals']['mem_total'] += node_data.get('maxmem', 0)
                cluster_data['totals']['mem_used'] += node_data.get('mem', 0)
            
            # Count VMs
            try:
                resources = mgr.get_vm_resources()
                for r in resources:
                    if r.get('type') == 'qemu':
                        if r.get('status') == 'running':
                            cluster_data['totals']['vms_running'] += 1
                        else:
                            cluster_data['totals']['vms_stopped'] += 1
                    else:
                        if r.get('status') == 'running':
                            cluster_data['totals']['cts_running'] += 1
                        else:
                            cluster_data['totals']['cts_stopped'] += 1
            except:
                pass
            
            snapshot['clusters'][cluster_id] = cluster_data
            
        except Exception as e:
            logging.debug(f"Failed to collect metrics for {cluster_id}: {e}")
    
    return snapshot


def metrics_collector_loop():
    """Background thread that collects metrics every 5 minutes
    
    updated for SQLite
    """
    global _metrics_collector_running
    
    while _metrics_collector_running:
        try:
            snapshot = collect_metrics_snapshot()
            
            # Save directly to SQLite
            save_metrics_snapshot(snapshot)
            
        except Exception as e:
            logging.error(f"Metrics collector error: {e}")
        
        # Sleep 5 minutes
        for _ in range(300):
            if not _metrics_collector_running:
                break
            time.sleep(1)


def start_metrics_collector():
    """Start the metrics collector"""
    global _metrics_collector_running
    
    _metrics_collector_running = True
    thread = threading.Thread(target=metrics_collector_loop, daemon=True)
    thread.start()
    logging.info("Metrics collector started")



