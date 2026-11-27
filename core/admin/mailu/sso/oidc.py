import base64
import binascii
import hashlib
import json
import math
import secrets
import time
from urllib.parse import urlencode

import flask
import flask_login
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa, utils as crypto_utils
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from flask import current_app as app
from flask_babel import lazy_gettext as _

from mailu import auth_flow, models, passkeys as passkey_utils, signin, utils


JWT_ALGORITHMS = {
    'EdDSA': ('eddsa', None),
    'ES256': ('ecdsa', SHA256()),
    'ES384': ('ecdsa', SHA384()),
    'ES512': ('ecdsa', SHA512()),
    'RS256': ('rsa', SHA256()),
    'RS384': ('rsa', SHA384()),
    'RS512': ('rsa', SHA512()),
}

DEFAULT_JWT_ALGORITHMS = {'EdDSA', 'ES256', 'RS256'}

JWK_KEY_TYPES = {
    'EdDSA': 'OKP',
    'ES256': 'EC',
    'ES384': 'EC',
    'ES512': 'EC',
    'RS256': 'RSA',
    'RS384': 'RSA',
    'RS512': 'RSA',
}

EC_CURVES = {
    'P-256': ec.SECP256R1(),
    'P-384': ec.SECP384R1(),
    'P-521': ec.SECP521R1(),
}

EC_ALG_PARAMS = {
    'ES256': ('P-256', 32),
    'ES384': ('P-384', 48),
    'ES512': ('P-521', 66),
}

ID_TOKEN_ENVELOPE_CLAIMS = {'iss', 'sub', 'aud', 'azp', 'exp', 'iat', 'nbf', 'nonce'}


def enabled():
    return bool(app.config.get('OIDC_ENABLED'))


def redirect_uri():
    configured = app.config.get('OIDC_REDIRECT_URI')
    if configured:
        return configured
    return flask.url_for('sso.oidc_callback', _external=True)


def _cache_seconds():
    configured = app.config.get('OIDC_JWKS_CACHE_SECONDS')
    return 3600 if configured is None else max(0, int(configured))


def _clock_skew_seconds():
    configured = app.config.get('OIDC_CLOCK_SKEW_SECONDS')
    return 60 if configured is None else max(0, int(configured))


def _fetch_discovery(discovery_url):
    ttl = _cache_seconds()
    cached = app.config.get('_OIDC_DISCOVERY_CACHE')
    now = time.time()
    if ttl > 0 and cached and cached['url'] == discovery_url and cached['expires_at'] > now:
        return cached['data']

    response = requests.get(discovery_url, headers={'Accept': 'application/json'}, timeout=10)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError('invalid OIDC discovery document')
    if ttl > 0:
        app.config['_OIDC_DISCOVERY_CACHE'] = {
            'url': discovery_url,
            'data': data,
            'expires_at': now + ttl,
        }
    return data


def provider_config():
    discovery_url = app.config.get('OIDC_DISCOVERY_URL')
    data = _fetch_discovery(discovery_url) if discovery_url else {}

    authorization_endpoint = app.config.get('OIDC_AUTHORIZATION_ENDPOINT') or data.get('authorization_endpoint')
    token_endpoint = app.config.get('OIDC_TOKEN_ENDPOINT') or data.get('token_endpoint')
    userinfo_endpoint = app.config.get('OIDC_USERINFO_ENDPOINT') or data.get('userinfo_endpoint') or ''
    jwks_uri = app.config.get('OIDC_JWKS_URI') or data.get('jwks_uri')
    issuer = app.config.get('OIDC_ISSUER') or data.get('issuer') or ''

    if not authorization_endpoint or not token_endpoint or not jwks_uri:
        raise RuntimeError('OIDC is enabled but provider endpoints are incomplete')

    return {
        'authorization_endpoint': authorization_endpoint,
        'token_endpoint': token_endpoint,
        'userinfo_endpoint': userinfo_endpoint,
        'jwks_uri': jwks_uri,
        'issuer': issuer,
    }


def _base64url_decode(value):
    if not isinstance(value, str) or not value:
        raise ValueError('invalid base64url value')
    padding_len = (-len(value)) % 4
    try:
        return base64.urlsafe_b64decode(value + ('=' * padding_len))
    except (ValueError, binascii.Error) as exc:
        raise ValueError('invalid base64url encoding') from exc


def _base64url_uint(value):
    return int.from_bytes(_base64url_decode(value), 'big')


def _load_jwt_part(value):
    try:
        data = json.loads(_base64url_decode(value))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError('invalid JWT JSON payload') from exc
    if not isinstance(data, dict):
        raise ValueError('JWT part must be a JSON object')
    return data


def _code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


def _clear_oidc_session():
    flask.session.pop('oidc_state', None)
    flask.session.pop('oidc_nonce', None)
    flask.session.pop('oidc_code_verifier', None)


def authorize_url():
    client_id = app.config.get('OIDC_CLIENT_ID')
    if not client_id:
        raise RuntimeError('OIDC is enabled but OIDC_CLIENT_ID is not configured')
    config = provider_config()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    flask.session['oidc_state'] = state
    flask.session['oidc_nonce'] = nonce
    flask.session['oidc_code_verifier'] = code_verifier

    query = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': redirect_uri(),
        'scope': app.config.get('OIDC_SCOPES') or 'openid email profile',
        'state': state,
        'nonce': nonce,
        'code_challenge': _code_challenge(code_verifier),
        'code_challenge_method': 'S256',
    }
    separator = '&' if '?' in config['authorization_endpoint'] else '?'
    return f'{config["authorization_endpoint"]}{separator}{urlencode(query)}'


def exchange_code(code, config=None):
    config = config or provider_config()
    code_verifier = flask.session.pop('oidc_code_verifier', '')
    if not code_verifier:
        raise ValueError('missing PKCE code verifier')
    client_id = app.config['OIDC_CLIENT_ID']
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri(),
        'client_id': client_id,
        'code_verifier': code_verifier,
    }
    auth = None
    headers = {'Accept': 'application/json'}
    method = app.config.get('OIDC_CLIENT_AUTH_METHOD') or 'client_secret_basic'
    secret = app.config.get('OIDC_CLIENT_SECRET')
    if method == 'client_secret_basic':
        if secret:
            auth = (client_id, secret)
    elif method == 'client_secret_post':
        if secret:
            data['client_secret'] = secret
    elif method == 'none':
        pass
    else:
        raise ValueError(f'unsupported OIDC_CLIENT_AUTH_METHOD: {method}')
    response = requests.post(config['token_endpoint'], data=data, headers=headers, auth=auth, timeout=10)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError('invalid token response')
    return payload


def _fetch_jwks(jwks_uri, force_refresh=False):
    ttl = _cache_seconds()
    cached = app.config.get('_OIDC_JWKS_CACHE')
    now = time.time()
    if not force_refresh and ttl > 0 and cached and cached['uri'] == jwks_uri and cached['expires_at'] > now:
        return cached['jwks'], True

    response = requests.get(jwks_uri, headers={'Accept': 'application/json'}, timeout=10)
    response.raise_for_status()
    jwks = response.json()
    if not isinstance(jwks, dict) or not isinstance(jwks.get('keys'), list):
        raise ValueError('invalid JWKS document')
    if ttl > 0:
        app.config['_OIDC_JWKS_CACHE'] = {
            'uri': jwks_uri,
            'jwks': jwks,
            'expires_at': now + ttl,
        }
    return jwks, False


def fetch_jwks(jwks_uri, force_refresh=False):
    jwks, _ = _fetch_jwks(jwks_uri, force_refresh=force_refresh)
    return jwks


def _allowed_algorithms():
    configured = app.config.get('OIDC_JWT_ALGORITHMS')
    if not configured:
        return DEFAULT_JWT_ALGORITHMS
    if isinstance(configured, str):
        return {s for s in configured.replace(' ', '').split(',') if s}
    return set(configured)


def _jwk_matches(header, jwk):
    if not isinstance(jwk, dict):
        return False
    alg = header.get('alg')
    if jwk.get('kty') != JWK_KEY_TYPES.get(alg):
        return False
    if alg in EC_ALG_PARAMS and jwk.get('crv') != EC_ALG_PARAMS[alg][0]:
        return False
    if alg == 'EdDSA' and jwk.get('crv') not in ('Ed25519', 'Ed448'):
        return False
    if jwk.get('use') not in (None, 'sig'):
        return False
    key_ops = jwk.get('key_ops')
    if key_ops is not None and (not isinstance(key_ops, list) or 'verify' not in key_ops):
        return False
    if header.get('kid') and jwk.get('kid') != header.get('kid'):
        return False
    if jwk.get('alg') and jwk.get('alg') != alg:
        return False
    return True


def _public_key_from_jwk(jwk):
    kty = jwk.get('kty')
    if kty == 'RSA':
        numbers = rsa.RSAPublicNumbers(
            e=_base64url_uint(jwk['e']),
            n=_base64url_uint(jwk['n']),
        )
        return numbers.public_key()
    if kty == 'EC':
        curve = EC_CURVES.get(jwk.get('crv'))
        if not curve:
            raise ValueError('unsupported EC JWK curve')
        numbers = ec.EllipticCurvePublicNumbers(
            x=_base64url_uint(jwk['x']),
            y=_base64url_uint(jwk['y']),
            curve=curve,
        )
        return numbers.public_key()
    if kty == 'OKP':
        crv = jwk.get('crv')
        if crv == 'Ed25519':
            return ed25519.Ed25519PublicKey.from_public_bytes(_base64url_decode(jwk['x']))
        if crv == 'Ed448':
            return ed448.Ed448PublicKey.from_public_bytes(_base64url_decode(jwk['x']))
    raise ValueError('unsupported JWK key type')


def _ecdsa_signature_from_jose(signature, coord_size):
    if len(signature) != coord_size * 2:
        raise ValueError('invalid ECDSA signature length')
    r = int.from_bytes(signature[:coord_size], 'big')
    s = int.from_bytes(signature[coord_size:], 'big')
    return crypto_utils.encode_dss_signature(r, s)


def _verify_signature(header, signing_input, signature, jwks):
    alg = header.get('alg')
    allowed = _allowed_algorithms()
    if not isinstance(alg, str) or alg not in allowed or alg not in JWT_ALGORITHMS:
        raise ValueError('unsupported or disallowed JWT algorithm')

    candidates = [jwk for jwk in jwks.get('keys', []) if _jwk_matches(header, jwk)]
    if not candidates:
        raise ValueError('no matching JWK')

    family, hash_algorithm = JWT_ALGORITHMS[alg]
    for jwk in candidates:
        try:
            public_key = _public_key_from_jwk(jwk)
            if family == 'rsa':
                public_key.verify(signature, signing_input, padding.PKCS1v15(), hash_algorithm)
            elif family == 'ecdsa':
                coord_size = EC_ALG_PARAMS[alg][1]
                public_key.verify(_ecdsa_signature_from_jose(signature, coord_size), signing_input, ec.ECDSA(hash_algorithm))
            elif family == 'eddsa':
                public_key.verify(signature, signing_input)
            else:
                raise ValueError('unsupported JWT algorithm family')
            return
        except (InvalidSignature, ValueError, KeyError, TypeError):
            continue
    raise ValueError('invalid JWT signature')


def _numeric_date(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return float(value)


def _validate_jwt_claims(claims, config=None):
    config = config or provider_config()
    now = time.time()
    leeway = _clock_skew_seconds()
    client_id = app.config['OIDC_CLIENT_ID']

    iss = claims.get('iss')
    if not isinstance(iss, str) or not iss:
        raise ValueError('missing JWT issuer')
    if config.get('issuer') and iss != config['issuer']:
        raise ValueError('invalid JWT issuer')

    sub = claims.get('sub')
    if not isinstance(sub, str) or not sub:
        raise ValueError('missing JWT subject')

    aud = claims.get('aud')
    if isinstance(aud, str):
        audiences = [aud]
    elif isinstance(aud, list) and all(isinstance(item, str) for item in aud):
        audiences = aud
    else:
        raise ValueError('missing JWT audience')
    if client_id not in audiences:
        raise ValueError('invalid JWT audience')
    azp = claims.get('azp')
    if azp is not None and azp != client_id:
        raise ValueError('invalid JWT authorized party')
    if len(audiences) > 1 and azp != client_id:
        raise ValueError('missing JWT authorized party')

    exp = _numeric_date(claims.get('exp'))
    if exp is None or now > exp + leeway:
        raise ValueError('expired JWT')
    if 'nbf' in claims:
        nbf = _numeric_date(claims['nbf'])
        if nbf is None or now + leeway < nbf:
            raise ValueError('JWT not yet valid')
    iat = _numeric_date(claims.get('iat'))
    if iat is None or now + leeway < iat:
        raise ValueError('invalid JWT issued-at')

    expected_nonce = flask.session.pop('oidc_nonce', None)
    received_nonce = claims.get('nonce')
    if (not expected_nonce or not isinstance(received_nonce, str)
            or not secrets.compare_digest(expected_nonce, received_nonce)):
        raise ValueError('invalid JWT nonce')


def validate_id_token(id_token, config=None):
    if not isinstance(id_token, str):
        raise ValueError('invalid JWT structure')
    parts = id_token.split('.')
    if len(parts) != 3:
        raise ValueError('invalid JWT structure')
    header = _load_jwt_part(parts[0])
    claims = _load_jwt_part(parts[1])
    signing_input = f'{parts[0]}.{parts[1]}'.encode('ascii')
    signature = _base64url_decode(parts[2])

    config = config or provider_config()
    jwks, from_cache = _fetch_jwks(config['jwks_uri'])
    try:
        _verify_signature(header, signing_input, signature, jwks)
    except ValueError:
        if not from_cache:
            raise
        jwks, _ = _fetch_jwks(config['jwks_uri'], force_refresh=True)
        _verify_signature(header, signing_input, signature, jwks)
    _validate_jwt_claims(claims, config=config)
    return claims


def fetch_userinfo(access_token, config=None):
    config = config or provider_config()
    response = requests.get(
        config['userinfo_endpoint'],
        headers={'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError('invalid UserInfo response')
    return data


def _allowed_domain(email):
    allowed = app.config.get('OIDC_ALLOWED_DOMAINS')
    if not allowed:
        return True
    if isinstance(allowed, str):
        allowed = {s for s in allowed.lower().replace(' ', '').split(',') if s}
    domain = email.rsplit('@', 1)[1]
    return domain in allowed


def _display_name_from_claims(claims):
    claim_name = app.config.get('OIDC_DISPLAY_NAME_CLAIM')
    if not claim_name:
        return ''
    value = claims.get(claim_name)
    if not isinstance(value, str):
        return ''
    return value.strip()[:160]


def _user_from_email(email, displayed_name=''):
    user = models.User.get(email)
    if user:
        if not user.enabled:
            flask.current_app.logger.warning('OIDC login failed for %s: user is disabled', email)
            return None
        return user

    if not app.config.get('OIDC_CREATE_USER'):
        return None

    localpart, domain_name = email.rsplit('@', 1)
    domain = models.db.session.get(models.Domain, domain_name)
    if not domain:
        return None
    if domain.max_users != -1 and len(domain.users) >= domain.max_users:
        return None

    user = models.User(localpart=localpart, domain=domain, displayed_name=displayed_name)
    user.set_password(secrets.token_urlsafe(), keep_sessions=set(flask.session))
    models.db.session.add(user)
    models.db.session.commit()
    user.send_welcome()
    return user


def merge_userinfo_claims(id_token_claims, userinfo_claims):
    if not isinstance(userinfo_claims, dict):
        raise ValueError('invalid UserInfo response')
    id_sub = id_token_claims.get('sub')
    userinfo_sub = userinfo_claims.get('sub')
    if (not isinstance(id_sub, str) or not isinstance(userinfo_sub, str)
            or not secrets.compare_digest(id_sub, userinfo_sub)):
        raise ValueError('UserInfo subject does not match ID token subject')
    claims = dict(id_token_claims)
    for key, value in userinfo_claims.items():
        if key not in ID_TOKEN_ENVELOPE_CLAIMS:
            claims[key] = value
    return claims


def resolve_user_from_claims(claims):
    email_claim = app.config.get('OIDC_EMAIL_CLAIM') or 'email'
    raw_email = claims.get(email_claim)
    email = raw_email.strip().lower() if isinstance(raw_email, str) else ''
    if not utils.is_valid_email(email):
        flask.current_app.logger.warning('OIDC login failed: missing or invalid email claim')
        return None

    if app.config.get('OIDC_REQUIRE_EMAIL_VERIFIED') and claims.get('email_verified') is not True:
        flask.current_app.logger.warning('OIDC login failed for %s: email is not verified', email)
        return None

    if not _allowed_domain(email):
        flask.current_app.logger.warning('OIDC login failed for %s: domain is not allowed', email)
        return None

    displayed_name = _display_name_from_claims(claims)
    user = _user_from_email(email, displayed_name=displayed_name)
    if not user:
        flask.current_app.logger.warning('OIDC login failed for %s: user does not exist or cannot be created', email)
        return None
    return user


def validate_callback_state():
    expected = flask.session.pop('oidc_state', None)
    received = flask.request.args.get('state')
    return bool(expected and received and secrets.compare_digest(expected, received))


def login_failed(message):
    flask.flash(message, 'error')
    return flask.redirect(flask.url_for('sso.login'))


def handle_callback(clear_webmail_cookies=None):
    if error := flask.request.args.get('error'):
        _clear_oidc_session()
        description = flask.request.args.get('error_description') or error
        flask.current_app.logger.warning('OIDC provider returned an error: %s', description)
        return login_failed(_('OpenID Connect login failed'))

    if not validate_callback_state():
        _clear_oidc_session()
        flask.current_app.logger.warning('OIDC login failed: invalid state')
        return login_failed(_('OpenID Connect login failed'))

    code = flask.request.args.get('code')
    if not code:
        _clear_oidc_session()
        flask.current_app.logger.warning('OIDC login failed: missing authorization code')
        return login_failed(_('OpenID Connect login failed'))

    try:
        config = provider_config()
        token = exchange_code(code, config=config)
        id_token = token.get('id_token')
        if not isinstance(id_token, str) or not id_token:
            flask.current_app.logger.warning('OIDC login failed: token response omitted id_token')
            return login_failed(_('OpenID Connect login failed'))
        claims = validate_id_token(id_token, config=config)
        access_token = token.get('access_token')
        if config.get('userinfo_endpoint') and isinstance(access_token, str) and access_token:
            userinfo = fetch_userinfo(access_token, config=config)
            claims = merge_userinfo_claims(claims, userinfo)
        user = resolve_user_from_claims(claims)
    except Exception:
        flask.current_app.logger.exception('OIDC login failed')
        return login_failed(_('OpenID Connect login failed'))
    finally:
        _clear_oidc_session()

    if not user:
        return login_failed(_('OpenID Connect login failed'))

    destination = signin.resolve()
    login_destination = destination
    signin.clear()
    passkey_utils.clear_password_passkey_nudge(flask.session)
    flask.session.regenerate()
    flask_login.login_user(user)

    client_ip = flask.request.headers.get('X-Real-IP', flask.request.remote_addr)
    client_port = flask.request.headers.get('X-Real-Port', None)
    flask.current_app.logger.info(
        'Login attempt for: %s/sso/%s from: %s/%s: success: oidc',
        user.email, flask.request.headers.get('X-Forwarded-Proto'),
        client_ip, client_port,
    )

    actions = [
        action for action in auth_flow.user_required_actions(user)
        if action != 'password_change'
    ]
    if actions:
        auth_flow.require_actions(flask.session, actions, destination)
        destination = flask.url_for(auth_flow.ACTION_ENDPOINTS[actions[0]])

    response = flask.redirect(destination)
    if clear_webmail_cookies is not None:
        response = clear_webmail_cookies(response)
    return signin.remember_preference(response, login_destination)
