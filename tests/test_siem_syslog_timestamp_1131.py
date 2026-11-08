# #1131: the SIEM syslog target wrote the audit timestamp as it is stored, naive local
# time from datetime.now().isoformat(). RFC 5424 6.2.3 makes the TIME-OFFSET part of
# TIMESTAMP mandatory, so strict receivers (Grafana Alloy's rfc5424 parser) dropped every
# line while lenient ones (rsyslog) took them. The header now carries the instant in UTC
# with a Z, read from the naive value as local time. MK Oct 2026

import os
import re
import time
from datetime import datetime, timezone

import pytest

from pegaprox.api.siem import _to_syslog_5424, _rfc5424_timestamp

# RFC 5424 TIMESTAMP: FULL-DATE "T" PARTIAL-TIME TIME-OFFSET, SECFRAC at most 6 digits
_TS = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$')


@pytest.fixture
def berlin_tz():
    old = os.environ.get('TZ')
    os.environ['TZ'] = 'Europe/Berlin'
    time.tzset()
    yield
    if old is None:
        os.environ.pop('TZ', None)
    else:
        os.environ['TZ'] = old
    time.tzset()


def _header_ts(line):
    return line.split(' ')[1]


def test_the_header_timestamp_carries_an_offset():
    line = _to_syslog_5424({'timestamp': datetime.now().isoformat(), 'action': 'siem.test'})
    assert _TS.match(_header_ts(line)), line


def test_a_naive_audit_time_is_read_as_local_time(berlin_tz):
    # 14:43 in Berlin during summer time is 12:43 UTC
    assert _rfc5424_timestamp('2026-10-07T14:43:06.197965') == '2026-10-07T12:43:06.197965Z'


def test_an_aware_or_zulu_value_keeps_its_instant():
    assert _rfc5424_timestamp('2026-10-07T12:43:06+00:00') == '2026-10-07T12:43:06.000000Z'
    assert _rfc5424_timestamp('2026-10-07T12:43:06Z') == '2026-10-07T12:43:06.000000Z'
    assert _rfc5424_timestamp('2026-10-07T14:43:06+02:00') == '2026-10-07T12:43:06.000000Z'


@pytest.mark.parametrize('value', [None, '', 'not a time'])
def test_a_missing_or_broken_value_falls_back_to_now(value):
    ts = _rfc5424_timestamp(value)
    assert _TS.match(ts), ts
    sent = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
    assert abs((datetime.now(timezone.utc) - sent).total_seconds()) < 5


def test_the_rest_of_the_line_is_unchanged():
    line = _to_syslog_5424({'timestamp': '2026-10-07T12:43:06', 'action': 'siem.test',
                            'user': 'alice'}, facility='authpriv')
    assert line.startswith('<86>1 ')
    assert ' pegaprox - siem.test - user=alice ' in line
