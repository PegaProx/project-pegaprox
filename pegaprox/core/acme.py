# MK: Mar 2026 - Lightweight ACME client for ACME-compatible CAs (#96, #249)
# Supports Let's Encrypt + custom ACME endpoints (StepCA, etc)
# Uses only cryptography + requests (no extra deps), HTTP-01 challenge

import os
import json
import time
import logging
import hashlib
import base64
import requests
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ACME_DIRECTORY_PROD = 'https://acme-v02.api.letsencrypt.org/directory'
ACME_DIRECTORY_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'

# challenge tokens currently being served — { token: key_authorization }
_pending_challenges = {}

# DNS-01 requests waiting for the admin to publish the TXT record.
_pending_dns_challenges = {}


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


def _get_directory_url(staging=False, directory_url=None):
    """Resolve the ACME directory URL, defaulting to Let's Encrypt."""
    custom = (directory_url or '').strip()
    if custom:
        return custom
    return ACME_DIRECTORY_STAGING if staging else ACME_DIRECTORY_PROD


def _dns01_value(key_authorization):
    """Return the DNS-01 TXT value for a key authorization."""
    return _b64url(hashlib.sha256(key_authorization.encode('utf-8')).digest())


def _dns01_record_name(domain):
    """Return the DNS-01 TXT record name for an ACME identifier."""
    identifier = (domain or '').strip().rstrip('.')
    if identifier.startswith('*.'):
        identifier = identifier[2:]
    return f"_acme-challenge.{identifier}".rstrip('.')


def _rfc2136_algorithm(name):
    """Map a UI algorithm name to dnspython's TSIG algorithm constants."""
    import dns.tsig
    algorithms = {
        'hmac-md5': getattr(dns.tsig, 'HMAC_MD5', None),
        'hmac-sha1': getattr(dns.tsig, 'HMAC_SHA1', None),
        'hmac-sha224': getattr(dns.tsig, 'HMAC_SHA224', None),
        'hmac-sha256': getattr(dns.tsig, 'HMAC_SHA256', None),
        'hmac-sha384': getattr(dns.tsig, 'HMAC_SHA384', None),
        'hmac-sha512': getattr(dns.tsig, 'HMAC_SHA512', None),
    }
    return algorithms.get((name or 'hmac-sha512').lower())


def _rfc2136_update(config, dns_name, dns_value, action='present'):
    """Create or remove the ACME DNS-01 TXT record via RFC 2136 dynamic DNS."""
    try:
        import dns.name
        import dns.query
        import dns.tsigkeyring
        import dns.update
    except ImportError:
        return {'success': False, 'message': 'dnspython is required for RFC 2136 DNS updates'}

    nameserver = (config.get('nameserver') or '').strip()
    zone = (config.get('zone') or '').strip().rstrip('.')
    key_name = (config.get('key_name') or '').strip()
    secret = (config.get('secret') or '').strip()
    algorithm_name = (config.get('algorithm') or 'hmac-sha512').strip().lower()
    port = int(config.get('port') or 53)
    ttl = int(config.get('ttl') or 60)

    if not nameserver or not zone or not key_name or not secret:
        return {'success': False, 'message': 'RFC 2136 nameserver, zone, key name and secret are required'}

    algorithm = _rfc2136_algorithm(algorithm_name)
    if not algorithm:
        return {'success': False, 'message': 'Unsupported RFC 2136 TSIG algorithm'}

    try:
        zone_name = dns.name.from_text(zone + '.')
        record_name = dns.name.from_text(dns_name.rstrip('.') + '.').relativize(zone_name)
        keyring = dns.tsigkeyring.from_text({key_name: secret})
        update = dns.update.Update(zone_name, keyring=keyring, keyname=key_name, keyalgorithm=algorithm)

        if action == 'delete':
            update.delete(record_name, 'TXT', dns_value)
        else:
            update.replace(record_name, ttl, 'TXT', dns_value)

        dns.query.tcp(update, nameserver, port=port, timeout=10)
        return {'success': True}
    except Exception as e:
        logging.error(f"[ACME] RFC 2136 update failed: {e}")
        return {'success': False, 'message': f'RFC 2136 DNS update failed: {e}'}


def _validate_challenge(authz_url, challenge_url, account_key, nonce, kid, token=None):
    """Notify ACME that the selected challenge is ready and poll authorization."""
    ch_resp = _signed_request(challenge_url, {}, account_key, nonce, kid)
    nonce = ch_resp.headers.get('Replay-Nonce', nonce)

    for attempt in range(30):
        time.sleep(2)
        poll_resp = _signed_request(authz_url, None, account_key, nonce, kid)
        nonce = poll_resp.headers.get('Replay-Nonce', nonce)
        authz_status = poll_resp.json()

        status = authz_status.get('status')
        if status == 'valid':
            logging.info("[ACME] Challenge validated!")
            return {'success': True, 'nonce': nonce}
        if status == 'invalid':
            ch_errors = []
            for ch in authz_status.get('challenges', []):
                if ch.get('error'):
                    ch_errors.append(ch['error'].get('detail', str(ch['error'])))
            if token:
                _pending_challenges.pop(token, None)
            return {'success': False, 'message': f"Challenge failed: {'; '.join(ch_errors) or 'unknown error'}"}

    if token:
        _pending_challenges.pop(token, None)
    return {'success': False, 'message': 'Challenge validation timed out (60s)'}


def _finalize_order(domain, ssl_dir, order, order_url, account_key, nonce, kid):
    """Generate the domain key/CSR, finalize the ACME order, and save cert files."""
    domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(domain_key, hashes.SHA256())
    )
    csr_der = csr.public_bytes(serialization.Encoding.DER)

    finalize_url = order['finalize']
    fin_payload = {'csr': _b64url(csr_der)}
    fin_resp = _signed_request(finalize_url, fin_payload, account_key, nonce, kid)
    nonce = fin_resp.headers.get('Replay-Nonce', nonce)

    if fin_resp.status_code not in (200, 201):
        err = fin_resp.json()
        return {'success': False, 'message': f"Finalize failed: {err.get('detail', err)}"}

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

    cert_url = order_data['certificate']
    cert_resp = _signed_request(cert_url, None, account_key, nonce, kid)
    cert_pem = cert_resp.text

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


def _create_order(domain, email, ssl_dir, staging=False, directory_url=None):
    """Create an ACME order and return the selected authorization context."""
    acme_url = _get_directory_url(staging=staging, directory_url=directory_url)
    account_key_path = os.path.join(ssl_dir, 'acme_account.key')

    env = 'custom' if (directory_url or '').strip() else ('staging' if staging else 'production')
    logging.info(f"[ACME] Starting certificate request for {domain} ({env}) via {acme_url}")
    try:
        from pegaprox.utils.url_security import sanitize_outbound_url, SsrfError
        sanitize_outbound_url(acme_url)
    except SsrfError as guard_err:
        return {'success': False, 'message': f'ACME directory URL rejected: {guard_err}'}

    dir_resp = requests.get(acme_url, timeout=15)
    dir_resp.raise_for_status()
    directory = dir_resp.json()

    account_key = _load_or_create_account_key(account_key_path)

    nonce = _get_nonce(directory)
    reg_payload = {'termsOfServiceAgreed': True}
    if email:
        reg_payload['contact'] = [f'mailto:{email}']

    reg_resp = _signed_request(directory['newAccount'], reg_payload, account_key, nonce)
    nonce = reg_resp.headers.get('Replay-Nonce', nonce)
    kid = reg_resp.headers['Location']
    logging.info(f"[ACME] Account registered/found: {kid}")

    order_payload = {'identifiers': [{'type': 'dns', 'value': domain}]}
    order_resp = _signed_request(directory['newOrder'], order_payload, account_key, nonce, kid)
    nonce = order_resp.headers.get('Replay-Nonce', nonce)

    if order_resp.status_code not in (200, 201):
        err = order_resp.json()
        return {'success': False, 'message': f"Order failed: {err.get('detail', err)}"}

    order = order_resp.json()
    authz_url = order['authorizations'][0]
    authz_resp = _signed_request(authz_url, None, account_key, nonce, kid)
    nonce = authz_resp.headers.get('Replay-Nonce', nonce)

    return {
        'success': True,
        'account_key': account_key,
        'nonce': nonce,
        'kid': kid,
        'order': order,
        'order_url': order_resp.headers.get('Location', ''),
        'authz_url': authz_url,
        'authz': authz_resp.json(),
    }


def request_certificate(domain, email, ssl_dir, staging=False, directory_url=None, challenge_type='http-01', dns_provider='manual', dns_config=None):
    """
    Request an ACME certificate via HTTP-01 challenge.
    Supports Let's Encrypt and custom ACME endpoints (StepCA, etc).

    Returns dict with 'success', 'message', optionally 'cert_path', 'key_path', 'expires'.
    The caller must ensure /.well-known/acme-challenge/<token> is served on port 80.
    """
    try:
        if challenge_type == 'dns-01':
            return prepare_dns01_challenge(
                domain, email, ssl_dir, staging=staging, directory_url=directory_url,
                dns_provider=dns_provider, dns_config=dns_config
            )
        if challenge_type != 'http-01':
            return {'success': False, 'message': 'Invalid ACME challenge type'}

        context = _create_order(domain, email, ssl_dir, staging=staging, directory_url=directory_url)
        if not context.get('success'):
            return context
        account_key = context['account_key']
        nonce = context['nonce']
        kid = context['kid']
        order = context['order']
        order_url = context['order_url']
        authz_url = context['authz_url']
        authz = context['authz']

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

        result = _validate_challenge(authz_url, http_challenge['url'], account_key, nonce, kid, token=token)
        if not result.get('success'):
            return result
        nonce = result['nonce']

        _pending_challenges.pop(token, None)
        return _finalize_order(domain, ssl_dir, order, order_url, account_key, nonce, kid)

    except Exception as e:
        logging.error(f"[ACME] Certificate request failed: {e}")
        # cleanup pending challenge
        _pending_challenges.clear()
        return {'success': False, 'message': str(e)}


def prepare_dns01_challenge(domain, email, ssl_dir, staging=False, directory_url=None, dns_provider='manual', dns_config=None):
    """Prepare a DNS-01 challenge and return the TXT record the admin must create."""
    try:
        context = _create_order(domain, email, ssl_dir, staging=staging, directory_url=directory_url)
        if not context.get('success'):
            return context

        dns_challenge = None
        for ch in context['authz'].get('challenges', []):
            if ch['type'] == 'dns-01':
                dns_challenge = ch
                break

        if not dns_challenge:
            return {'success': False, 'message': 'No DNS-01 challenge offered by ACME server'}

        token = dns_challenge['token']
        key_authorization = f"{token}.{_jwk_thumbprint(context['account_key'])}"
        state_id = secrets.token_urlsafe(24)
        dns_name = _dns01_record_name(domain)
        dns_value = _dns01_value(key_authorization)

        if dns_provider == 'rfc2136':
            dns_config = dns_config or {}
            update_result = _rfc2136_update(dns_config, dns_name, dns_value, action='present')
            if not update_result.get('success'):
                return update_result

            propagation_seconds = max(0, min(600, int(dns_config.get('propagation_seconds') or 30)))
            if propagation_seconds:
                logging.info(f"[ACME] Waiting {propagation_seconds}s for RFC 2136 DNS propagation")
                time.sleep(propagation_seconds)

            result = _validate_challenge(
                context['authz_url'],
                dns_challenge['url'],
                context['account_key'],
                context['nonce'],
                context['kid'],
            )
            cleanup = _rfc2136_update(dns_config, dns_name, dns_value, action='delete')
            if not cleanup.get('success'):
                logging.warning(f"[ACME] RFC 2136 TXT cleanup failed: {cleanup.get('message')}")
            if not result.get('success'):
                return result

            return _finalize_order(
                domain,
                ssl_dir,
                context['order'],
                context['order_url'],
                context['account_key'],
                result['nonce'],
                context['kid'],
            )
        if dns_provider != 'manual':
            return {'success': False, 'message': 'Unsupported DNS-01 provider'}

        _pending_dns_challenges[state_id] = {
            **context,
            'domain': domain,
            'challenge_url': dns_challenge['url'],
            'expires_at': time.time() + 3600,
        }

        logging.info(f"[ACME] DNS-01 challenge prepared for {domain}")
        return {
            'success': False,
            'pending_dns': True,
            'message': 'Create the DNS TXT record, wait for propagation, then continue validation.',
            'challenge_id': state_id,
            'dns_name': dns_name,
            'dns_value': dns_value,
        }
    except Exception as e:
        logging.error(f"[ACME] DNS-01 preparation failed: {e}")
        return {'success': False, 'message': str(e)}


def complete_dns01_challenge(challenge_id, ssl_dir):
    """Continue a pending DNS-01 challenge after the TXT record has propagated."""
    context = _pending_dns_challenges.get(challenge_id)
    if not context:
        return {'success': False, 'message': 'DNS-01 challenge was not found or has expired'}
    if context.get('expires_at', 0) < time.time():
        _pending_dns_challenges.pop(challenge_id, None)
        return {'success': False, 'message': 'DNS-01 challenge expired; request a new challenge'}

    try:
        result = _validate_challenge(
            context['authz_url'],
            context['challenge_url'],
            context['account_key'],
            context['nonce'],
            context['kid'],
        )
        if not result.get('success'):
            return result

        _pending_dns_challenges.pop(challenge_id, None)
        return _finalize_order(
            context['domain'],
            ssl_dir,
            context['order'],
            context['order_url'],
            context['account_key'],
            result['nonce'],
            context['kid'],
        )
    except Exception as e:
        logging.error(f"[ACME] DNS-01 completion failed: {e}")
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


def check_and_renew(domain, email, ssl_dir, staging=False, days_before=30, directory_url=None, challenge_type='http-01', dns_provider='manual', dns_config=None):
    """Check if cert needs renewal and renew if so. Returns True if renewed."""
    info = get_cert_info(ssl_dir)
    if not info:
        return False

    # renew any ACME-managed cert (LE or custom CA), skip only self-signed
    if info.get('is_self_signed'):
        return False

    if info['days_left'] > days_before:
        logging.debug(f"[ACME] Cert still valid for {info['days_left']} days, no renewal needed")
        return False

    logging.info(f"[ACME] Cert expires in {info['days_left']} days, renewing...")

    result = request_certificate(
        domain, email, ssl_dir, staging=staging, directory_url=directory_url,
        challenge_type=challenge_type, dns_provider=dns_provider, dns_config=dns_config
    )
    if result['success']:
        logging.info(f"[ACME] Renewal successful! New expiry: {result.get('expires')}")
        return True
    if result.get('pending_dns'):
        logging.info(
            f"[ACME] DNS-01 renewal challenge pending for {domain}: "
            f"{result.get('dns_name')} TXT {result.get('dns_value')}"
        )
        return False
    else:
        logging.error(f"[ACME] Renewal failed: {result['message']}")
        return False
