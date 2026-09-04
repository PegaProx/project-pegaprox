# Regression test for #778 (zobsg): paramiko needs a bare host, but IPv6 addresses arrive bracketed
# ("[fe80::1]") from the node-IP cache. Without stripping the brackets, ssh.connect() fails for every
# IPv6-only node (node shell + host-key fetch). vms.py now de-brackets before connecting.


def _debracket(h):
    # mirrors the inline expression in vms.py so its behavior is pinned directly
    return h[1:-1] if h and h.startswith('[') and h.endswith(']') else h


def test_debracket_logic():
    assert _debracket('[fe80::1]') == 'fe80::1'
    assert _debracket('[2001:db8::42]') == '2001:db8::42'
    assert _debracket('192.168.1.5') == '192.168.1.5'              # IPv4 untouched
    assert _debracket('node1.example.com') == 'node1.example.com'  # hostname untouched
    assert _debracket('') == ''
    assert _debracket(None) is None


def test_vms_ssh_connect_uses_debracketed_host():
    import pegaprox.api.vms as vms
    with open(vms.__file__, 'r') as fh:
        src = fh.read()
    # both ssh call sites must hand paramiko the de-bracketed host, not the raw node_ip
    assert "ssh.connect(_ssh_host" in src, "ssh_handler must connect via _ssh_host (#778)"
    assert "hostname=_ssh_host" in src, "node_shell proxy must connect via _ssh_host (#778)"
    assert src.count("node_ip[1:-1] if node_ip and node_ip.startswith('[')") >= 2, \
        "expected the IPv6 de-bracket guard at both ssh sites (#778)"
