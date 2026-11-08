# The test harness must not reach the database of the checkout it runs in (config/pegaprox.db,
# a developer's live instance): the metrics collector that pegaprox.api.reports starts in
# every process wrote snapshots of the tests' fake clusters into it, and the heavy reads
# (core/dbcrypto.py) read their history from it, so a test passed or failed on whatever
# that database held.
import os
import time

import pegaprox.background.metrics as metrics
import pegaprox.constants as constants
import pegaprox.core.db as dbmod


def test_a_test_process_takes_no_metrics_snapshots_of_its_own(monkeypatch):
    saved = []
    monkeypatch.setattr(metrics, 'save_metrics_snapshot', lambda snap: saved.append(snap))
    metrics.start_metrics_collector()
    try:
        time.sleep(0.5)
    finally:
        metrics._metrics_collector_running = False
    assert saved == []


def test_the_heavy_reads_open_the_test_database(db):
    assert constants.DATABASE_FILE == dbmod.DATABASE_FILE
    assert os.path.abspath(constants.DATABASE_FILE) != os.path.abspath(os.path.join('config', 'pegaprox.db'))
