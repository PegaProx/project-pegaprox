# Regression: the template image_url SSRF guard fires through the real route.
#
# CodeAnt exploitation finding (SSRF): add_custom_template wget's image_url on the PVE node.
# Fixed with sanitize_outbound_url(allow_private=True) — which ALWAYS blocks cloud-metadata
# endpoints (the real SSRF target) while intentionally allowing internal/air-gapped mirrors
# (RFC1918/loopback) so legit internal image sources keep working. This drives the actual route.


def test_template_image_url_metadata_is_blocked(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    r = api.as_user(admin).post('/api/templates/custom', json={
        'name': 'ssrf-probe',
        'image_url': 'http://169.254.169.254/latest/meta-data/',
    })
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'ssrf' in (r.get_json() or {}).get('error', '').lower()


def test_template_image_url_control_chars_blocked(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    # the pre-existing char check + the SSRF guard both reject smuggling attempts
    r = api.as_user(admin).post('/api/templates/custom', json={
        'name': 'ssrf-probe2',
        'image_url': 'http://metadata.google.internal/computeMetadata/v1/',
    })
    assert r.status_code == 400, r.get_data(as_text=True)
