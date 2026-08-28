import json
import queue
from unittest.mock import patch

from pegaprox.globals import sse_clients, sse_clients_lock
from pegaprox.utils.realtime import broadcast_sse


def test_resource_sse_filters_each_clients_vm_rows_server_side():
    alice_queue = queue.Queue()
    admin_queue = queue.Queue()
    with sse_clients_lock:
        sse_clients.clear()
        sse_clients.update({
            'alice-client': {
                'queue': alice_queue,
                'user': 'alice',
                'clusters': ['cluster-a'],
            },
            'admin-client': {
                'queue': admin_queue,
                'user': 'admin',
                'clusters': None,
            },
        })

    resources = [
        {'vmid': 101, 'type': 'qemu', 'guest_mem_percent': 20.0},
        {'vmid': 202, 'type': 'qemu', 'guest_mem_percent': 90.0},
    ]

    def authorized(rows, cluster_id, username):
        assert cluster_id == 'cluster-a'
        return rows if username == 'admin' else [row for row in rows if row['vmid'] == 101]

    try:
        with patch('pegaprox.utils.realtime._filter_sse_resources_for_user', side_effect=authorized):
            broadcast_sse('resources', resources, 'cluster-a')

        alice_payload = json.loads(alice_queue.get_nowait())
        admin_payload = json.loads(admin_queue.get_nowait())
        assert [row['vmid'] for row in alice_payload['data']] == [101]
        assert [row['vmid'] for row in admin_payload['data']] == [101, 202]
        assert all(row['vmid'] != 202 for row in alice_payload['data'])
    finally:
        with sse_clients_lock:
            sse_clients.clear()
