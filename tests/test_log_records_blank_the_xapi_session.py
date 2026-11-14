"""Every log record writes an XAPI session_id as ***, on loggers created later too.

XCP-ng's HTTP handlers take the pool session in the query string. requests names the url
of a call that fails in its exception text, and urllib3 logs every request line with it
in --debug. The per-cluster XCPng_<name> loggers are created with their own handlers when
a pool is added, after startup, and reach no filter of their own, so the record sanitizer
app.py installs blanks the value as well. scrub_session_id is the one helper behind it,
core/xhm.py and core/xcpng.py.
MK Nov 2026
"""
import io
import logging

import pytest
import requests

from pegaprox.utils.sanitization import install_log_record_sanitizer, scrub_session_id

SESSION = 'OpaqueRef:5b1d0c77-9e1a-4c1d-pool-login'
ENCODED = SESSION.replace(':', '%3A')


@pytest.mark.parametrize('text, kept', [
    (f'PUT https://xcp/import_raw_vdi?session_id={SESSION}&vdi=u1&format=raw',
     'https://xcp/import_raw_vdi?session_id=***&vdi=u1&format=raw'),
    (f'Max retries exceeded with url: /rrd_updates?session_id={ENCODED}&start=1 (Caused by X)',
     'url: /rrd_updates?session_id=***&start=1 (Caused by X)'),
    (f'/export_raw_vdi?vdi=u1&session_id={ENCODED} (Caused by X)',
     '/export_raw_vdi?vdi=u1&session_id=*** (Caused by X)'),
    # repr(e) of a requests error: the url sits inside the quotes of MaxRetryError(...)
    (f"ConnectionError(MaxRetryError('url: /rrd_updates?session_id={ENCODED}'))",
     "MaxRetryError('url: /rrd_updates?session_id=***'))"),
    (f'[session_id={SESSION}]', '[session_id=***]'),
    (f'(session_id={SESSION})', '(session_id=***)'),
    (f"<a href='/x?session_id={SESSION}'>", "<a href='/x?session_id=***'>"),
    (f"{{'force': 'true', 'session_id': '{SESSION}'}}", "{'force': 'true', 'session_id': '***'}"),
    (f'next=%2Fimport_raw_vdi%3Fsession_id%3D{ENCODED}%26vdi%3Du1', 'session_id%3D***%26vdi%3Du1'),
    # the repr of a keyword argument, blanks around the =, a bare colon
    (f"Session(session_id='{SESSION}', host='xcp')", "Session(session_id='***', host='xcp')"),
    (f'Session(session_id="{SESSION}")', 'Session(session_id="***")'),
    (f'session_id = {SESSION} expired', 'session_id = *** expired'),
    (f'session_id: {SESSION}', 'session_id: ***'),
])
def test_the_value_goes_and_the_rest_stays(text, kept):
    out = scrub_session_id(text)
    assert SESSION not in out and ENCODED not in out and '5b1d0c77' not in out, out
    assert kept in out, out
    assert scrub_session_id(out) == out


def test_text_without_a_session_is_left_as_it_is():
    for text in ('session_id: missing in the reply', 'no session here', 'session_id=', '',
                 # a line of code in a traceback
                 "session_id = request.headers.get('X-Session-ID')", "p = {'session_id': sid}"):
        assert scrub_session_id(text) == text
    assert scrub_session_id(None) is None
    assert scrub_session_id(ValueError(f'url: /x?session_id={SESSION}')) == 'url: /x?session_id=***'


def _later_logger(name, formatter=None):
    """A logger made after startup the way XcpngManager.__init__ makes one."""
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(formatter or logging.Formatter('%(levelname)s: %(message)s'))
    lg = logging.getLogger(name)
    lg.handlers = [h]
    lg.setLevel(logging.DEBUG)
    lg.propagate = False
    return lg, buf


def _connection_error():
    path = requests.Request('GET', 'https://xcp.example/rrd_updates',
                            params={'session_id': SESSION, 'start': 1}).prepare().path_url
    return requests.exceptions.ConnectionError(
        f"HTTPSConnectionPool(host='xcp.example', port=443): Max retries exceeded with url: {path} "
        "(Caused by NewConnectionError('Failed to establish a new connection: [Errno 111]'))")


def test_a_brand_new_cluster_logger_writes_no_session():
    install_log_record_sanitizer()
    lg, buf = _later_logger('XCPng_created_after_startup')

    lg.error('_rrd_fetch %s: %s', 'rrd_updates', _connection_error())   # an exception, not a str
    lg.error(f'upload_to_storage: PUT https://xcp/import_raw_vdi?session_id={SESSION}&vdi=u1 failed')
    # urllib3's request line in --debug, with the url as an argument
    lg.debug('%s://%s:%s "%s %s %s" %s %s', 'https', 'xcp.example', 443, 'GET',
             f'/rrd_updates?session_id={ENCODED}&start=1', 'HTTP/1.1', 200, None)

    out = buf.getvalue()
    assert SESSION not in out and ENCODED not in out, out
    assert 'url: /rrd_updates?session_id=***&start=1 (Caused by' in out, out
    assert 'import_raw_vdi?session_id=***&vdi=u1 failed' in out, out
    assert '"GET /rrd_updates?session_id=***&start=1 HTTP/1.1" 200' in out, out
    assert out.count('\n') == 3


def test_a_traceback_keeps_its_lines_but_not_the_session():
    install_log_record_sanitizer()
    lg, buf = _later_logger('XCPng_traceback_after_startup')
    try:
        raise _connection_error()
    except requests.exceptions.ConnectionError:
        lg.exception('_rrd_fetch rrd_updates')

    out = buf.getvalue()
    assert 'Traceback (most recent call last)' in out, out
    assert 'requests.exceptions.ConnectionError: HTTPSConnectionPool' in out, out
    assert 'session_id=***&start=1' in out, out
    assert SESSION not in out and ENCODED not in out, out


def test_a_traceback_without_a_session_stays_with_the_formatter():
    class _Own(logging.Formatter):
        def formatException(self, ei):
            return 'rendered by the handler formatter'

    install_log_record_sanitizer()
    lg, buf = _later_logger('XCPng_own_formatter', _Own('%(message)s'))
    try:
        raise RuntimeError('pool master went away')
    except RuntimeError:
        lg.exception('refresh failed')
    assert buf.getvalue() == 'refresh failed\nrendered by the handler formatter\n'


def test_a_session_in_an_exception_the_traceback_was_raised_from_goes_too():
    install_log_record_sanitizer()
    lg, buf = _later_logger('XCPng_chained_traceback')
    try:
        try:
            raise _connection_error()
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError('chart read failed') from e
    except RuntimeError:
        lg.exception('refresh failed')
    try:
        try:
            raise _connection_error()
        except requests.exceptions.ConnectionError:
            raise KeyError('legend')
    except KeyError:
        lg.exception('parse failed')

    out = buf.getvalue()
    assert 'The above exception was the direct cause of the following exception' in out, out
    assert 'During handling of the above exception, another exception occurred' in out, out
    assert out.count('session_id=***&start=1') == 2, out
    assert SESSION not in out and ENCODED not in out, out


def test_a_traceback_without_a_session_is_rendered_once(monkeypatch):
    rendered = []
    real = logging.Formatter.formatException

    def _counting(self, ei):
        rendered.append(type(self).__name__)
        return real(self, ei)

    monkeypatch.setattr(logging.Formatter, 'formatException', _counting)
    install_log_record_sanitizer()
    lg, buf = _later_logger('XCPng_rendered_once')
    try:
        try:
            raise ConnectionError('pool master went away')
        except ConnectionError:
            raise RuntimeError('refresh failed')
    except RuntimeError:
        lg.exception('refresh failed')

    # by the handler, and not one more time when the record was built
    assert rendered == ['Formatter'], rendered
    assert 'RuntimeError: refresh failed' in buf.getvalue()
