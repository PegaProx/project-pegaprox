"""An ESXi host in the cluster list reports its TLS verification the way it is set.

ssl_verification is True where the certificate is verified, on every cluster, and
VMwareManager.ssl_verify means the same. The facade that puts an ESXi host among the
clusters stored the opposite, so the config export told the Re-configure dialog that a
host without verification verified, and the other way round.
"""
import types

import pytest

from pegaprox.core.esxi_cluster import ESXiClusterManager


def _host(ssl_verify):
    vmw = types.SimpleNamespace(host='10.0.0.9', username='root', password='x', ssl_verify=ssl_verify,
                                enabled=True, name='esx9', connected=True, api_version='8.0')
    return ESXiClusterManager('esxi1', vmw)


@pytest.mark.parametrize('verify', [False, True])
def test_the_facade_config_carries_the_hosts_setting(verify):
    assert _host(verify).config.ssl_verification is verify


@pytest.mark.parametrize('verify', [False, True])
def test_the_config_export_reports_it(api, seed, verify):
    api.set_manager('esxi1', _host(verify))
    admin = api.as_user(seed.user('root_admin', role='admin'))
    r = admin.get('/api/clusters/esxi1/config/export')
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['cluster_type'] == 'esxi' and body['ssl_verification'] is verify, body
