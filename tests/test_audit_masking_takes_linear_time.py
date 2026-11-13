"""Masking an audit row reads its details once, however they are made up.

The mask for an older download row looked for its URL with a pattern that went back over
every ' from http' of a row without a '...'. A row whose details repeat that, a long alert
name say, took seconds per read, and every route that hands audit rows out (the audit page,
the search, the timeline, the support bundle) ran it with the whole server waiting.
"""
import time

from pegaprox.utils.audit import masked_details

LONG = 'Started download: x' + ' from http://h' * 8000          # about 110 KB, no '...'


def test_a_long_row_without_dots_is_handed_back_at_once():
    t = time.monotonic()
    assert masked_details(LONG) == LONG
    assert time.monotonic() - t < 2.0


def test_a_long_row_with_dots_at_the_end_is_masked_at_once():
    row = 'Started download: x from http://u:p@ssw0rd@10.0.0.9/a.iso' + ' from http://h' * 8000 + '...'
    t = time.monotonic()
    shown = masked_details(row)
    assert time.monotonic() - t < 2.0
    assert 'ssw0rd' not in shown and shown.endswith('...')
    assert shown.startswith('Started download: x from http://10.0.0.9/')


def test_a_row_as_the_download_route_wrote_it_reads_as_before():
    row = 'Started download: debian.iso from http://mirroruser:p@ssw0rd@93.184.216.34/is...'
    assert masked_details(row) == 'Started download: debian.iso from http://93.184.216.34/[REDACTED]...'
    cut = 'Started download: debian.iso from http://mirroruser:Sec r3t@93.1...'
    assert masked_details(cut) == 'Started download: debian.iso from http://[REDACTED]...'
    plain = 'Started download: debian.iso from mirror ... nothing to mask'
    assert masked_details(plain) == plain
