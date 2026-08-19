# GHSA-hmcf-9q7f-vx35 (senti-man) — DNS-rebinding TOCTOU on the shared SSRF guard.
#
# End-to-end proof that the ISO/image download route now PINS the vetted IP into the URL it hands to
# the Proxmox node, so the node (which re-resolves + fetches with verify-certificates=0) cannot be
# rebound to loopback/RFC1918/metadata. We drive the real Flask route with a faked cluster manager
# and a monkeypatched resolver (the standard, offline way to model a rebinding domain), and assert
# the URL forwarded to PVE is an IP literal — there is no hostname left for a second lookup to rebind.

from unittest.mock import MagicMock

import pegaprox.utils.url_security as url_security


def _fake_resolver(mapping):
    import ipaddress
    import socket

    def _resolve(host):
        if host in mapping:
            return [ipaddress.ip_address(ip) for ip in mapping[host]]
        raise socket.gaierror(f'name not known: {host}')
    return _resolve


def test_iso_download_pins_ip_before_delegating_to_pve(api, seed, monkeypatch):
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['storage.upload'])

    # the attacker domain resolves 'public' for our check; pinning must bake THAT ip into the URL so
    # the node never performs the second (rebindable) lookup
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'rebind.attacker.example': ['93.184.216.34']}))

    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True
    fake.host = '127.0.0.1'
    fake.api_port = 8006
    sess = MagicMock()
    resp = MagicMock(); resp.status_code = 200; resp.json.return_value = {'data': 'UPID:dl'}
    sess.post.return_value = resp
    fake._create_session.return_value = sess
    api.set_manager('cluster_1', fake)

    r = api.as_user(bob).post('/api/clusters/cluster_1/datastores/local/download-url', json={
        'url': 'http://rebind.attacker.example/evil.iso',
        'filename': 'evil.iso',
        'node': 'node1',   # provide the node so the handler skips the nodes lookup
    })
    assert r.status_code == 200, r.get_data(as_text=True)

    # the download_data PVE receives must carry the PINNED ip literal, not the reboundable hostname
    assert sess.post.called
    posted = sess.post.call_args.kwargs.get('data') or (sess.post.call_args.args[1] if len(sess.post.call_args.args) > 1 else {})
    assert posted.get('url') == 'http://93.184.216.34/evil.iso', posted.get('url')


def test_iso_download_rejects_host_resolving_to_metadata(api, seed, monkeypatch):
    seed.tenant('acme', clusters=['cluster_1'])
    bob = seed.user('bob', role='user', tenant_id='acme', permissions=['storage.upload'])
    monkeypatch.setattr(url_security, '_resolve_all',
                        _fake_resolver({'sneaky.example': ['169.254.169.254']}))
    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True; fake.host = '127.0.0.1'; fake.api_port = 8006
    api.set_manager('cluster_1', fake)

    r = api.as_user(bob).post('/api/clusters/cluster_1/datastores/local/download-url', json={
        'url': 'http://sneaky.example/x.iso', 'node': 'node1',
    })
    assert r.status_code == 400
    assert 'ssrf' in r.get_data(as_text=True).lower()
