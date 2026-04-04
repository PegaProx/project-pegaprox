# MK: Mar 2026 - Lightweight ACME client for ACME-compatible CAs (#96)
# Uses only cryptography + requests (no extra deps)
# Supports HTTP-01 challenge only for now

import os
import json
import time
import logging
import hashlib
import base64
import requests

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ACME_DIRECTORY_PROD = 'https://acme-v02.api.letsencrypt.org/directory'
ACME_DIRECTORY_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'

# challenge tokens currently being served — { token: key_authorization }
_pending_challenges = {}


def _b64url(data):
    """Base64url encode without padding"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(s):
    s = s + '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _load_or_create_account_key(key_path):
    """Load existing account key or generate a new one"""
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)
    return key


def _jwk_thumbprint(account_key):
    """Compute JWK thumbprint (RFC 7638)"""
    pub = account_key.public_key().public_numbers()
    jwk = {
        'e': _b64url(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, 'big')),
        'kty': 'RSA',
        'n': _b64url(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, 'big')),
    }
    jwk_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(jwk_json.encode('utf-8')).digest()
    return _b64url(digest)


def _jws_header(account_key, url, nonce, kid=None):
    """Build JWS protected header"""
    header = {'alg': 'RS256', 'nonce': nonce, 'url': url}
    if kid:
        header['kid'] = kid
    else:
        pub = account_key.public_key().public_numbers()
        header['jwk'] = {
            'kty': 'RSA',
            'e': _b64url(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, 'big')),
            'n': _b64url(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, 'big')),
        }
    return header


def _signed_request(url, payload, account_key, nonce, kid=None):
    """Send a JWS-signed POST to an ACME endpoint"""
    header = _jws_header(account_key, url, nonce, kid)
    protected = _b64url(json.dumps(header))

    if payload is None:
        # POST-as-GET
        payload_b64 = ''
    else:
        payload_b64 = _b64url(json.dumps(payload))

    sign_input = f"{protected}.{payload_b64}".encode('ascii')
    signature = account_key.sign(sign_input, padding.PKCS1v15(), hashes.SHA256())

    body = {
        'protected': protected,
        'payload': payload_b64,
        'signature': _b64url(signature),
    }
    resp = requests.post(url, json=body, headers={'Content-Type': 'application/jose+json'}, timeout=30)
    return resp


def _get_nonce(directory):
    resp = requests.head(directory['newNonce'], timeout=10)
    return resp.headers['Replay-Nonce']


def get_challenge_response(token):
    """Return the key authorization for a pending challenge token"""
    return _pending_challenges.get(token)


def get_directory_url(staging=False, directory_url=None):
    """Resolve the ACME directory URL, defaulting to Let's Encrypt."""
    custom_url = (directory_url or '').strip()
    if custom_url:
        return custom_url
    return ACME_DIRECTORY_STAGING if staging else ACME_DIRECTORY_PROD


def request_certificate(domain, email, ssl_dir, staging=False, directory_url=None):
    """
    Request an ACME certificate via HTTP-01 challenge.

    Returns dict with 'success', 'message', optionally 'cert_path', 'key_path', 'expires'.
    The caller must ensure /.well-known/acme-challenge/<token> is served on port 80.
    """
    acme_url = get_directory_url(staging=staging, directory_url=directory_url)
    account_key_path = os.path.join(ssl_dir, 'acme_account.key')

    try:
        # Step 1: Load directory
        environment = 'custom' if (directory_url or '').strip() else ('staging' if staging else 'production')
        logging.info(f"[ACME] Starting certificate request for {domain} ({environment}) via {acme_url}")
        dir_resp = requests.get(acme_url, timeout=15)
        dir_resp.raise_for_status()
        directory = dir_resp.json()

        # Step 2: Load/create account key
        account_key = _load_or_create_account_key(account_key_path)

        # Step 3: Register account (or find existing)
        nonce = _get_nonce(directory)
        reg_payload = {'termsOfServiceAgreed': True}
        if email:
            reg_payload['contact'] = [f'mailto:{email}']

        reg_resp = _signed_request(directory['newAccount'], reg_payload, account_key, nonce)
        nonce = reg_resp.headers.get('Replay-Nonce', nonce)
        kid = reg_resp.headers['Location']
        logging.info(f"[ACME] Account registered/found: {kid}")

        # Step 4: Create order
        order_payload = {'identifiers': [{'type': 'dns', 'value': domain}]}
        order_resp = _signed_request(directory['newOrder'], order_payload, account_key, nonce, kid)
        nonce = order_resp.headers.get('Replay-Nonce', nonce)

        if order_resp.status_code not in (200, 201):
            err = order_resp.json()
            return {'success': False, 'message': f"Order failed: {err.get('detail', err)}"}

        order = order_resp.json()
        order_url = order_resp.headers.get('Location', '')

        # Step 5: Get authorization + challenge
        authz_url = order['authorizations'][0]
        authz_resp = _signed_request(authz_url, None, account_key, nonce, kid)
        nonce = authz_resp.headers.get('Replay-Nonce', nonce)
        authz = authz_resp.json()

        http_challenge = None
        for ch in authz.get('challenges', []):
            if ch['type'] == 'http-01':
                http_challenge = ch
                break

        if not http_challenge:
            return {'success': False, 'message': 'No HTTP-01 challenge offered by ACME server'}

        # Step 6: Prepare challenge response
        token = http_challenge['token']
        thumbprint = _jwk_thumbprint(account_key)
        key_authorization = f"{token}.{thumbprint}"

        # Make it available via the Flask route
        _pending_challenges[token] = key_authorization
        logging.info(f"[ACME] Challenge token set, waiting for validation...")

        # Step 7: Tell ACME server we're ready
        challenge_url = http_challenge['url']
        ch_resp = _signed_request(challenge_url, {}, account_key, nonce, kid)
        nonce = ch_resp.headers.get('Replay-Nonce', nonce)

        # Step 8: Poll for validation
        for attempt in range(30):
            time.sleep(2)
            poll_resp = _signed_request(authz_url, None, account_key, nonce, kid)
            nonce = poll_resp.headers.get('Replay-Nonce', nonce)
            authz_status = poll_resp.json()

            status = authz_status.get('status')
            if status == 'valid':
                logging.info("[ACME] Challenge validated!")
                break
            elif status == 'invalid':
                ch_errors = []
                for ch in authz_status.get('challenges', []):
                    if ch.get('error'):
                        ch_errors.append(ch['error'].get('detail', str(ch['error'])))
                _pending_challenges.pop(token, None)
                return {'success': False, 'message': f"Challenge failed: {'; '.join(ch_errors) or 'unknown error'}"}
            # pending - keep waiting
        else:
            _pending_challenges.pop(token, None)
            return {'success': False, 'message': 'Challenge validation timed out (60s)'}

        _pending_challenges.pop(token, None)

        # Step 9: Generate domain private key + CSR
        domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
            .sign(domain_key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)

        # Step 10: Finalize order
        finalize_url = order['finalize']
        fin_payload = {'csr': _b64url(csr_der)}
        fin_resp = _signed_request(finalize_url, fin_payload, account_key, nonce, kid)
        nonce = fin_resp.headers.get('Replay-Nonce', nonce)

        if fin_resp.status_code not in (200, 201):
            err = fin_resp.json()
            return {'success': False, 'message': f"Finalize failed: {err.get('detail', err)}"}

        # Step 11: Poll order until certificate is ready
        order_data = fin_resp.json()
        for attempt in range(15):
            if order_data.get('status') == 'valid' and order_data.get('certificate'):
                break
            time.sleep(2)
            poll_resp = _signed_request(order_url, None, account_key, nonce, kid)
            nonce = poll_resp.headers.get('Replay-Nonce', nonce)
            order_data = poll_resp.json()
        else:
            return {'success': False, 'message': 'Timed out waiting for certificate'}

        # Step 12: Download certificate
        cert_url = order_data['certificate']
        cert_resp = _signed_request(cert_url, None, account_key, nonce, kid)
        cert_pem = cert_resp.text  # fullchain PEM

        # Step 13: Save cert + key
        os.makedirs(ssl_dir, exist_ok=True)
        cert_path = os.path.join(ssl_dir, 'cert.pem')
        key_path = os.path.join(ssl_dir, 'key.pem')

        with open(cert_path, 'w') as f:
            f.write(cert_pem)
        os.chmod(cert_path, 0o644)

        with open(key_path, 'wb') as f:
            f.write(domain_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        os.chmod(key_path, 0o600)

        # Parse expiry from cert
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
        expires = cert_obj.not_valid_after_utc.isoformat()

        logging.info(f"[ACME] Certificate saved! Expires: {expires}")
        return {
            'success': True,
            'message': f"Certificate issued for {domain}",
            'cert_path': cert_path,
            'key_path': key_path,
            'expires': expires,
        }

    except Exception as e:
        logging.error(f"[ACME] Certificate request failed: {e}")
        # cleanup pending challenge
        _pending_challenges.clear()
        return {'success': False, 'message': str(e)}


def get_cert_info(ssl_dir):
    """Get info about the current SSL certificate (issuer, expiry, etc.)"""
    cert_path = os.path.join(ssl_dir, 'cert.pem')
    if not os.path.exists(cert_path):
        return None

    try:
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())

        issuer_cn = ''
        for attr in cert.issuer:
            if attr.oid == NameOID.COMMON_NAME:
                issuer_cn = attr.value
                break

        subject_cn = ''
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                subject_cn = attr.value
                break

        # check if it's a Let's Encrypt cert
        issuer_org = ''
        for attr in cert.issuer:
            if attr.oid == NameOID.ORGANIZATION_NAME:
                issuer_org = attr.value
                break

        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        expires = cert.not_valid_after_utc
        days_left = (expires - now).days

        return {
            'subject': subject_cn,
            'issuer': issuer_cn,
            'issuer_org': issuer_org,
            'expires': expires.isoformat(),
            'days_left': days_left,
            'is_letsencrypt': 'let' in issuer_org.lower() and 'encrypt' in issuer_org.lower(),
            'is_self_signed': cert.issuer == cert.subject,
            'valid': days_left > 0,
        }
    except Exception as e:
        logging.error(f"[ACME] Failed to read cert info: {e}")
        return None


def check_and_renew(domain, email, ssl_dir, staging=False, days_before=30, directory_url=None):
    """Check if cert needs renewal and renew if so. Returns True if renewed."""
    info = get_cert_info(ssl_dir)
    if not info:
        return False

    if info['days_left'] > days_before:
        logging.debug(f"[ACME] Cert still valid for {info['days_left']} days, no renewal needed")
        return False

    logging.info(f"[ACME] Cert expires in {info['days_left']} days, renewing...")
    result = request_certificate(domain, email, ssl_dir, staging=staging, directory_url=directory_url)
    if result['success']:
        logging.info(f"[ACME] Renewal successful! New expiry: {result.get('expires')}")
        return True
    else:
        logging.error(f"[ACME] Renewal failed: {result['message']}")
        return False
