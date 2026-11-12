"""The settings read leaves out the push keypair.

GET /api/settings/server masks every sealed secret of the server settings, and handed out
the push keypair as it is stored, its private key sealed with the field key. The browsers
take the public half from /api/push/vapid-key, and the form neither shows nor saves the
pair. The read leaves it out now; a save of the form keeps the stored pair, and push still
signs with it. MK
"""
import base64

import pytest

VAPID = 'webpush_vapid_keypair'


@pytest.fixture
def admin(api, seed):
    from pegaprox.api import push
    push._load_vapid()
    return api.as_user(seed.user('root', role='admin'))


def _stored_pair():
    from pegaprox.core.db import get_db
    return get_db().get_server_settings()[VAPID]


def _signed_with(jwt, public_b64):
    """Whether the ES256 token verifies under the public key the browsers were given."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    def unb64(s):
        return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

    head, claims, sig = jwt.split('.')
    raw = unb64(sig)
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64(public_b64))
    try:
        key.verify(encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')),
                   f'{head}.{claims}'.encode('ascii'), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def test_the_read_holds_no_part_of_the_keypair(admin):
    stored = _stored_pair()
    assert stored['private_pem'].startswith(('aes256:', 'enc:'))

    r = admin.get('/api/settings/server')

    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert VAPID not in r.get_json()
    text = r.get_data(as_text=True)
    assert stored['private_pem'] not in text and 'private_pem' not in text


def test_a_save_of_what_the_form_read_keeps_the_pair_and_push_signs_with_it(admin):
    """The counterweight: the form never wrote the pair, so leaving it out of the read
    changes nothing a save keeps."""
    from pegaprox.api import push
    before = _stored_pair()
    public = admin.get('/api/push/vapid-key').get_json()['public_key']
    form = admin.get('/api/settings/server').get_json()

    r = admin.post('/api/settings/server', json=dict(form, session_timeout=7200))

    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert _stored_pair() == before
    assert push._load_vapid()['public_b64'] == public
    assert _signed_with(push._vapid_jwt('https://push.example'), public)
