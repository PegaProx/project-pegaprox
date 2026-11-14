"""A mirror login in a task log line goes whole, also when its password holds both a
blank and an '@'.

The part without blanks was tried first and ended at the first '@', so
'u:p@ss word@mirror/x' kept "ss word" in the line node viewers read.
"""
from pegaprox.utils.sanitization import mask_url_logins


def test_a_password_with_a_blank_and_an_at_goes_whole():
    line = 'downloading https://mirror:p@ss w0rd@93.184.216.34/isos/d.iso to /var/lib/vz'
    shown = mask_url_logins(line)
    assert shown == 'downloading https://[REDACTED]@93.184.216.34/isos/d.iso to /var/lib/vz'
    for part in ('mirror:', 'ss', 'w0rd'):
        assert part not in shown.split('://', 1)[1].split('@', 1)[0], shown


def test_the_lines_masked_before_read_as_before():
    assert (mask_url_logins('get http://u:p@ssw0rd@10.0.0.5/x.iso')
            == 'get http://[REDACTED]@10.0.0.5/x.iso')
    assert (mask_url_logins('get http://u:Sec r3t@10.0.0.5/x.iso')
            == 'get http://[REDACTED]@10.0.0.5/x.iso')
    assert mask_url_logins('see https://user@10.0.0.7 and more') == 'see https://[REDACTED]@10.0.0.7 and more'
    line = 'TASK ERROR: GET http://10.0.0.5:8006 failed for root@pam'
    assert mask_url_logins(line) == line
    assert (mask_url_logins('x http://a:b@h/p y http://c:d@e/f')
            == 'x http://[REDACTED]@h/p y http://[REDACTED]@e/f')
