"""The replication form sends '*/15' and '*/30'. Snapshot replication took them for no schedule and ran
every 6 hours, while the form went on showing what was chosen, and the staleness alert used the 6 hours too."""
import pytest

from pegaprox.background.cross_cluster_replication import _parse_interval_seconds


@pytest.mark.parametrize('schedule,seconds', [('*/15', 900), ('*/30', 1800), (' */15 ', 900), ('*/15 * * * *', 900),
                                              ('0 */6 * * *', 21600), ('0 */1 * * *', 3600), ('0 0 * * *', 86400)])
def test_what_the_form_offers(schedule, seconds):
    assert _parse_interval_seconds(schedule) == seconds


@pytest.mark.parametrize('schedule', ['', 'nonsense', '*/x', '1 2 3'])
def test_what_it_cannot_read_stays_the_old_fallback(schedule):
    assert _parse_interval_seconds(schedule) == 21600


def test_the_lower_limit_still_holds():
    assert _parse_interval_seconds('*/1') == 300
