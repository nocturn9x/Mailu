import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from mailu import configuration, create_app_from_config, models, passkeys as passkey_utils
from mailu.sso import oidc


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def b64url_uint(value):
    return b64url(value.to_bytes((value.bit_length() + 7) // 8, 'big'))


def jwk_from_rsa_key(private_key, kid='test-rsa-key'):
    numbers = private_key.public_key().public_numbers()
    return {
        'kty': 'RSA',
        'use': 'sig',
        'alg': 'RS256',
        'kid': kid,
        'n': b64url_uint(numbers.n),
        'e': b64url_uint(numbers.e),
    }


def jwk_from_ec_key(private_key, kid='test-ec-key'):
    numbers = private_key.public_key().public_numbers()
    return {
        'kty': 'EC',
        'use': 'sig',
        'alg': 'ES256',
        'kid': kid,
        'crv': 'P-256',
        'x': b64url_uint(numbers.x),
        'y': b64url_uint(numbers.y),
    }


def jwk_from_ed25519_key(private_key, kid='test-ed-key'):
    public_bytes = private_key.public_key().public_bytes_raw()
    return {
        'kty': 'OKP',
        'use': 'sig',
        'alg': 'EdDSA',
        'kid': kid,
        'crv': 'Ed25519',
        'x': b64url(public_bytes),
    }


def signed_rsa_id_token(private_key, claims, kid='test-rsa-key'):
    header = {'typ': 'JWT', 'alg': 'RS256', 'kid': kid}
    signing_input = '.'.join([
        b64url(json.dumps(header, separators=(',', ':')).encode('utf-8')),
        b64url(json.dumps(claims, separators=(',', ':')).encode('utf-8')),
    ])
    signature = private_key.sign(signing_input.encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
    return f'{signing_input}.{b64url(signature)}'


def signed_es256_id_token(private_key, claims, kid='test-ec-key'):
    header = {'typ': 'JWT', 'alg': 'ES256', 'kid': kid}
    signing_input = '.'.join([
        b64url(json.dumps(header, separators=(',', ':')).encode('utf-8')),
        b64url(json.dumps(claims, separators=(',', ':')).encode('utf-8')),
    ])
    der_signature = private_key.sign(signing_input.encode('ascii'), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_signature)
    signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    return f'{signing_input}.{b64url(signature)}'


def signed_eddsa_id_token(private_key, claims, kid='test-ed-key'):
    header = {'typ': 'JWT', 'alg': 'EdDSA', 'kid': kid}
    signing_input = '.'.join([
        b64url(json.dumps(header, separators=(',', ':')).encode('utf-8')),
        b64url(json.dumps(claims, separators=(',', ':')).encode('utf-8')),
    ])
    signature = private_key.sign(signing_input.encode('ascii'))
    return f'{signing_input}.{b64url(signature)}'


def configure_oidc(app, **overrides):
    app.config.update({
        'ADMIN': True,
        'WEBMAIL_AVAILABLE': 'roundcube',
        'OIDC_ENABLED': True,
        'OIDC_DISCOVERY_URL': '',
        'OIDC_ISSUER': 'https://idp.example.test/',
        'OIDC_AUTHORIZATION_ENDPOINT': 'https://idp.example.test/authorize',
        'OIDC_TOKEN_ENDPOINT': 'https://idp.example.test/token',
        'OIDC_USERINFO_ENDPOINT': 'https://idp.example.test/userinfo',
        'OIDC_JWKS_URI': 'https://idp.example.test/jwks.json',
        'OIDC_CLIENT_ID': 'mailu',
        'OIDC_CLIENT_SECRET': 'secret',
        'OIDC_CLIENT_AUTH_METHOD': 'client_secret_basic',
        'OIDC_REDIRECT_URI': 'https://mail.example.test/sso/oidc/callback',
        'OIDC_SCOPES': 'openid email profile',
        'OIDC_EMAIL_CLAIM': 'email',
        'OIDC_DISPLAY_NAME_CLAIM': 'name',
        'OIDC_REQUIRE_EMAIL_VERIFIED': True,
        'OIDC_CREATE_USER': False,
        'OIDC_ALLOWED_DOMAINS': set(),
        'OIDC_JWT_ALGORITHMS': {'EdDSA', 'ES256', 'RS256'},
        'OIDC_JWKS_CACHE_SECONDS': 3600,
        'OIDC_CLOCK_SKEW_SECONDS': 60,
        '_OIDC_JWKS_CACHE': None,
        '_OIDC_DISCOVERY_CACHE': None,
    })
    app.config.update(overrides)


def create_domain_and_user(email='user@example.com', enabled=True):
    domain_name = email.rsplit('@', 1)[1]
    domain = models.db.session.get(models.Domain, domain_name)
    if not domain:
        domain = models.Domain(name=domain_name)
        models.db.session.add(domain)
    user = models.User(localpart=email.split('@', 1)[0], domain=domain, enabled=enabled)
    user.set_password('password')
    models.db.session.add(user)
    models.db.session.commit()
    return user


def id_token_claims(app, client, email='user@example.com', nonce=None, sub=None, **extra):
    if nonce is None:
        with client.session_transaction() as session:
            nonce = session['oidc_nonce']
    now = int(time.time())
    claims = {
        'iss': app.config['OIDC_ISSUER'],
        'sub': sub or email,
        'aud': app.config['OIDC_CLIENT_ID'],
        'exp': now + 300,
        'iat': now,
        'nonce': nonce,
        'email_verified': True,
    }
    if email is not None:
        claims['email'] = email
    claims.update(extra)
    return claims


def start_oidc_login(client, path='/sso/oidc/login'):
    rv = client.get(path)
    assert rv.status_code == 302
    state = parse_qs(urlparse(rv.headers['Location']).query)['state'][0]
    return rv, state


def test_oidc_disabled_by_default(app, client):
    assert app.config['OIDC_ENABLED'] is False
    assert app.config['SESSION_COOKIE_SAMESITE'] == 'Strict'
    assert app.config['OIDC_JWT_ALGORITHMS'] == {'EdDSA', 'ES256', 'RS256'}
    assert client.get('/sso/oidc/login').status_code == 404
    assert client.get('/sso/oidc/callback').status_code == 404
    login_page = client.get('/sso/login')
    assert b'Sign in with OpenID Connect' not in login_page.data


def test_oidc_enabled_uses_samesite_lax_session_cookie(monkeypatch):
    monkeypatch.setenv('OIDC_ENABLED', 'true')
    cfg = configuration.ConfigManager()
    oidc_app = create_app_from_config(cfg)
    assert oidc_app.config['OIDC_ENABLED'] is True
    assert oidc_app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
    assert oidc_app.config['OIDC_JWT_ALGORITHMS'] == {'EdDSA', 'ES256', 'RS256'}


def test_login_page_shows_oidc_button_and_target(app, client):
    configure_oidc(app)
    page = client.get('/sso/login')
    assert b'Sign in with OpenID Connect' in page.data
    assert b'href="/sso/oidc/login"' in page.data

    admin_page = client.get('/sso/login/admin')
    assert b'href="/sso/oidc/login?target=admin"' in admin_page.data


def test_oidc_login_redirect_contains_state_nonce_and_pkce(app, client):
    configure_oidc(app)

    rv = client.get('/sso/oidc/login?target=admin')

    assert rv.status_code == 302
    location = rv.headers['Location']
    parsed = urlparse(location)
    query = parse_qs(parsed.query)
    assert location.startswith('https://idp.example.test/authorize?')
    assert query['response_type'] == ['code']
    assert query['client_id'] == ['mailu']
    assert query['redirect_uri'] == ['https://mail.example.test/sso/oidc/callback']
    assert query['scope'] == ['openid email profile']
    assert query['code_challenge_method'] == ['S256']
    with client.session_transaction() as session:
        assert query['state'] == [session['oidc_state']]
        assert query['nonce'] == [session['oidc_nonce']]
        expected_challenge = b64url(hashlib.sha256(session['oidc_code_verifier'].encode('ascii')).digest())
        assert query['code_challenge'] == [expected_challenge]


def test_oidc_login_invalid_target_returns_404(app, client):
    configure_oidc(app)
    assert client.get('/sso/oidc/login?target=evil').status_code == 404


def test_oidc_callback_rs256_logs_in_clears_webmail_cookies_and_remembers_target(app, client, monkeypatch):
    configure_oidc(app)
    user = create_domain_and_user()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {'keys': [jwk_from_rsa_key(private_key)]}
    captured = {}

    def fake_post(url, data=None, headers=None, auth=None, timeout=None):
        captured['token_request'] = data
        captured['auth'] = auth
        token = signed_rsa_id_token(private_key, id_token_claims(app, client, user.email))
        return FakeResponse({'access_token': 'access-token', 'id_token': token})

    def fake_get(url, headers=None, timeout=None):
        if url == app.config['OIDC_JWKS_URI']:
            return FakeResponse(jwks)
        assert headers['Authorization'] == 'Bearer access-token'
        return FakeResponse({'sub': user.email, 'email': user.email, 'email_verified': True})

    monkeypatch.setattr(oidc.requests, 'post', fake_post)
    monkeypatch.setattr(oidc.requests, 'get', fake_get)

    _, state = start_oidc_login(client, '/sso/oidc/login?target=admin')
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')

    assert rv.status_code == 302
    assert rv.headers['Location'] == '/admin'
    assert captured['token_request']['code'] == 'abc'
    assert captured['token_request']['code_verifier']
    assert captured['auth'] == ('mailu', 'secret')

    set_cookies = rv.headers.getlist('Set-Cookie')
    for cookie_name in ('roundcube_sessauth', 'roundcube_sessid', 'smsession'):
        assert any(c.startswith(f'{cookie_name}=empty;') for c in set_cookies)
    pref_cookie = client.get_cookie('mailu_signin_target', path='/sso')
    assert pref_cookie and pref_cookie.value == 'admin'

    with client.session_transaction() as session:
        assert session['_user_id'] == user.email
        assert 'signin_destination' not in session
        assert 'oidc_state' not in session
        assert 'oidc_nonce' not in session
        assert 'oidc_code_verifier' not in session
        flashes = session.get('_flashes', [])
        assert not any(passkey_utils.PASSWORD_NUDGE_MARKER in str(msg) for _, msg in flashes)


def test_oidc_callback_accepts_es256_id_token_without_userinfo(app, client, monkeypatch):
    configure_oidc(app, OIDC_USERINFO_ENDPOINT='')
    user = create_domain_and_user()
    private_key = ec.generate_private_key(ec.SECP256R1())
    jwks = {'keys': [jwk_from_ec_key(private_key)]}

    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'id_token': signed_es256_id_token(private_key, id_token_claims(app, client, user.email)),
    }))
    monkeypatch.setattr(oidc.requests, 'get', lambda url, **kwargs: FakeResponse(jwks) if url == app.config['OIDC_JWKS_URI'] else pytest.fail('unexpected GET'))

    _, state = start_oidc_login(client, '/sso/oidc/login?target=webmail')
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')

    assert rv.status_code == 302
    assert rv.headers['Location'] == '/webmail'
    with client.session_transaction() as session:
        assert session['_user_id'] == user.email


def test_oidc_callback_accepts_eddsa_id_token(app, client, monkeypatch):
    configure_oidc(app)
    user = create_domain_and_user()
    private_key = ed25519.Ed25519PrivateKey.generate()
    jwks = {'keys': [jwk_from_ed25519_key(private_key)]}

    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'access_token': 'access-token',
        'id_token': signed_eddsa_id_token(private_key, id_token_claims(app, client, user.email)),
    }))

    def fake_get(url, headers=None, timeout=None):
        if url == app.config['OIDC_JWKS_URI']:
            return FakeResponse(jwks)
        return FakeResponse({'sub': user.email, 'email': user.email, 'email_verified': True})

    monkeypatch.setattr(oidc.requests, 'get', fake_get)

    _, state = start_oidc_login(client, '/sso/oidc/login?target=admin')
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')

    assert rv.status_code == 302
    assert rv.headers['Location'] == '/admin'
    with client.session_transaction() as session:
        assert session['_user_id'] == user.email


def test_oidc_callback_preserves_oauth2_authorize_destination(app, client, monkeypatch):
    configure_oidc(app)
    user = create_domain_and_user()
    private_key = ed25519.Ed25519PrivateKey.generate()
    jwks = {'keys': [jwk_from_ed25519_key(private_key)]}

    oauth2_url = '/admin/oauth2/authorize?client_id=mailu&response_type=code&scope=imap&redirect_uri=http://127.0.0.1:9999/cb&code_challenge=abc&code_challenge_method=S256'
    start = client.get(oauth2_url)
    assert start.status_code == 302
    assert start.headers['Location'] == '/sso/login'

    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'access_token': 'access-token',
        'id_token': signed_eddsa_id_token(private_key, id_token_claims(app, client, user.email)),
    }))
    monkeypatch.setattr(oidc.requests, 'get', lambda url, **kwargs: FakeResponse(
        jwks if url == app.config['OIDC_JWKS_URI'] else {'sub': user.email, 'email': user.email, 'email_verified': True}
    ))

    _, state = start_oidc_login(client, '/sso/oidc/login')
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')

    assert rv.status_code == 302
    assert rv.headers['Location'] == oauth2_url
    with client.session_transaction() as session:
        assert session['_user_id'] == user.email


@pytest.mark.parametrize('alg', ['HS256', 'none'])
def test_oidc_callback_rejects_symmetric_and_none_algorithms(app, client, monkeypatch, alg):
    configure_oidc(app, OIDC_JWT_ALGORITHMS={alg, 'RS256'})
    user = create_domain_and_user()

    def fake_post(*args, **kwargs):
        header = {'typ': 'JWT', 'alg': alg}
        claims = id_token_claims(app, client, user.email)
        signing_input = '.'.join([
            b64url(json.dumps(header, separators=(',', ':')).encode('utf-8')),
            b64url(json.dumps(claims, separators=(',', ':')).encode('utf-8')),
        ])
        token = f'{signing_input}.{b64url(b"forged")}'
        return FakeResponse({'access_token': 'access-token', 'id_token': token})

    monkeypatch.setattr(oidc.requests, 'post', fake_post)
    monkeypatch.setattr(oidc.requests, 'get', lambda *args, **kwargs: FakeResponse({'keys': []}))

    _, state = start_oidc_login(client)
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')

    assert rv.status_code == 302
    assert rv.headers['Location'] == '/sso/login'
    with client.session_transaction() as session:
        assert '_user_id' not in session


def test_oidc_callback_rejects_invalid_state_and_preserves_pending_destination(app, client, monkeypatch):
    configure_oidc(app)
    create_domain_and_user()
    client.get('/admin/user/password')

    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: pytest.fail('token endpoint should not be called'))
    client.get('/sso/oidc/login')
    rv = client.get('/sso/oidc/callback?code=abc&state=wrong')

    assert rv.status_code == 302
    assert rv.headers['Location'] == '/sso/login'
    with client.session_transaction() as session:
        assert '_user_id' not in session
        assert session['signin_destination']['path'] == '/admin/user/password'


def test_oidc_callback_rejects_bad_signature_and_bad_nonce(app, client, monkeypatch):
    configure_oidc(app)
    user = create_domain_and_user()
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Wrong signing key
    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'access_token': 'access-token',
        'id_token': signed_rsa_id_token(signing_key, id_token_claims(app, client, user.email)),
    }))
    monkeypatch.setattr(oidc.requests, 'get', lambda *args, **kwargs: FakeResponse({'keys': [jwk_from_rsa_key(other_key)]}))
    _, state = start_oidc_login(client)
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302 and rv.headers['Location'] == '/sso/login'

    # Wrong nonce
    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'access_token': 'access-token',
        'id_token': signed_rsa_id_token(signing_key, id_token_claims(app, client, user.email, nonce='wrong')),
    }))
    monkeypatch.setattr(oidc.requests, 'get', lambda *args, **kwargs: FakeResponse({'keys': [jwk_from_rsa_key(signing_key)]}))
    _, state = start_oidc_login(client)
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302 and rv.headers['Location'] == '/sso/login'
    with client.session_transaction() as session:
        assert '_user_id' not in session


@pytest.mark.parametrize('claim_overrides', [
    {'iss': 'https://wrong-idp.example.test/'},
    {'aud': 'other-client'},
    {'aud': ['mailu', 'other-client']},
    {'aud': ['mailu', 'other-client'], 'azp': 'other-client'},
    {'azp': 'other-client'},
    {'exp': int(time.time()) - 120},
    {'nbf': int(time.time()) + 120},
    {'iat': int(time.time()) + 120},
])
def test_oidc_callback_rejects_invalid_jwt_claims(app, client, monkeypatch, claim_overrides):
    configure_oidc(app, OIDC_USERINFO_ENDPOINT='')
    user = create_domain_and_user()
    key = ed25519.Ed25519PrivateKey.generate()
    jwks = {'keys': [jwk_from_ed25519_key(key)]}

    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'id_token': signed_eddsa_id_token(key, id_token_claims(app, client, user.email, **claim_overrides)),
    }))
    monkeypatch.setattr(oidc.requests, 'get', lambda *args, **kwargs: FakeResponse(jwks))

    _, state = start_oidc_login(client)
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302
    assert rv.headers['Location'] == '/sso/login'
    with client.session_transaction() as session:
        assert '_user_id' not in session


def test_oidc_callback_refreshes_cached_jwks_on_key_rotation(app, client, monkeypatch):
    configure_oidc(app, OIDC_USERINFO_ENDPOINT='')
    user = create_domain_and_user()
    old_key = ed25519.Ed25519PrivateKey.generate()
    new_key = ed25519.Ed25519PrivateKey.generate()
    app.config['_OIDC_JWKS_CACHE'] = {
        'uri': app.config['OIDC_JWKS_URI'],
        'jwks': {'keys': [jwk_from_ed25519_key(old_key, kid='old-kid')]},
        'expires_at': time.time() + 3600,
    }
    fetches = []

    def fake_get(url, headers=None, timeout=None):
        fetches.append(url)
        return FakeResponse({'keys': [jwk_from_ed25519_key(new_key, kid='new-kid')]})

    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'id_token': signed_eddsa_id_token(new_key, id_token_claims(app, client, user.email), kid='new-kid'),
    }))
    monkeypatch.setattr(oidc.requests, 'get', fake_get)

    _, state = start_oidc_login(client, '/sso/oidc/login?target=admin')
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')

    assert rv.status_code == 302
    assert rv.headers['Location'] == '/admin'
    assert fetches == [app.config['OIDC_JWKS_URI']]


def test_oidc_callback_rejects_userinfo_subject_mismatch(app, client, monkeypatch):
    configure_oidc(app)
    user = create_domain_and_user()
    key = ed25519.Ed25519PrivateKey.generate()
    jwks = {'keys': [jwk_from_ed25519_key(key)]}

    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'access_token': 'access-token',
        'id_token': signed_eddsa_id_token(key, id_token_claims(app, client, user.email)),
    }))
    monkeypatch.setattr(oidc.requests, 'get', lambda url, **kwargs: FakeResponse(
        jwks if url == app.config['OIDC_JWKS_URI'] else {'sub': 'other@example.com', 'email': user.email, 'email_verified': True}
    ))

    _, state = start_oidc_login(client)
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302
    assert rv.headers['Location'] == '/sso/login'
    with client.session_transaction() as session:
        assert '_user_id' not in session


def test_oidc_callback_rejects_disabled_user(app, client, monkeypatch):
    configure_oidc(app, OIDC_USERINFO_ENDPOINT='')
    user = create_domain_and_user(enabled=False)
    key = ed25519.Ed25519PrivateKey.generate()
    jwks = {'keys': [jwk_from_ed25519_key(key)]}

    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'id_token': signed_eddsa_id_token(key, id_token_claims(app, client, user.email)),
    }))
    monkeypatch.setattr(oidc.requests, 'get', lambda *args, **kwargs: FakeResponse(jwks))

    _, state = start_oidc_login(client)
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302
    assert rv.headers['Location'] == '/sso/login'
    with client.session_transaction() as session:
        assert '_user_id' not in session


def test_oidc_callback_skips_password_change_and_respects_passkey_enrollment(app, client, monkeypatch):
    configure_oidc(app, OIDC_USERINFO_ENDPOINT='')
    user = create_domain_and_user()
    user.change_pw_next_login = True
    models.db.session.commit()
    key = ed25519.Ed25519PrivateKey.generate()
    jwks = {'keys': [jwk_from_ed25519_key(key)]}

    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'id_token': signed_eddsa_id_token(key, id_token_claims(app, client, user.email)),
    }))
    monkeypatch.setattr(oidc.requests, 'get', lambda *args, **kwargs: FakeResponse(jwks))

    _, state = start_oidc_login(client, '/sso/oidc/login?target=admin')
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302
    assert rv.headers['Location'] == '/admin'

    client.get('/sso/logout')
    user.passkey_enroll_next_login = True
    models.db.session.commit()

    _, state = start_oidc_login(client, '/sso/oidc/login?target=admin')
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302
    assert rv.headers['Location'] == '/admin/user/passkey-required'
    with client.session_transaction() as session:
        assert session['required_actions'] == ['passkey_enrollment']
        assert session['required_actions_destination'].endswith('/admin')


def test_oidc_callback_jit_creates_user_with_custom_claims_and_domain_restriction(app, client, monkeypatch):
    configure_oidc(
        app,
        OIDC_CREATE_USER=True,
        OIDC_ALLOWED_DOMAINS={'example.com'},
        OIDC_EMAIL_CLAIM='mail',
        OIDC_DISPLAY_NAME_CLAIM='display_name',
    )
    models.db.session.add_all([
        models.Domain(name='example.com'),
        models.Domain(name='blocked.org'),
    ])
    models.db.session.commit()

    key = ed25519.Ed25519PrivateKey.generate()
    jwks = {'keys': [jwk_from_ed25519_key(key)]}

    # Blocked domain rejected
    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'access_token': 'access-token',
        'id_token': signed_eddsa_id_token(key, id_token_claims(app, client, email=None, sub='nope@blocked.org', mail='nope@blocked.org')),
    }))
    monkeypatch.setattr(oidc.requests, 'get', lambda url, **kwargs: FakeResponse(
        jwks if url == app.config['OIDC_JWKS_URI'] else {'sub': 'nope@blocked.org', 'mail': 'nope@blocked.org', 'email_verified': True}
    ))
    _, state = start_oidc_login(client)
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302 and rv.headers['Location'] == '/sso/login'
    assert models.User.get('nope@blocked.org') is None

    # Allowed domain created with display name from UserInfo
    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'access_token': 'access-token',
        'id_token': signed_eddsa_id_token(key, id_token_claims(app, client, email=None, sub='new@example.com')),
    }))
    monkeypatch.setattr(oidc.requests, 'get', lambda url, **kwargs: FakeResponse(
        jwks if url == app.config['OIDC_JWKS_URI'] else {
            'sub': 'new@example.com',
            'mail': 'New@Example.com',
            'display_name': 'Alice Example',
            'email_verified': True,
        }
    ))
    _, state = start_oidc_login(client, '/sso/oidc/login?target=admin')
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302
    assert rv.headers['Location'] == '/admin'
    user = models.User.get('new@example.com')
    assert user is not None
    assert user.enabled is True
    assert user.displayed_name == 'Alice Example'
    with client.session_transaction() as session:
        assert session['_user_id'] == 'new@example.com'


def test_oidc_discovery_caching_and_client_secret_post(app, client, monkeypatch):
    configure_oidc(
        app,
        OIDC_DISCOVERY_URL='https://idp.example.test/.well-known/openid-configuration',
        OIDC_ISSUER='',
        OIDC_AUTHORIZATION_ENDPOINT='',
        OIDC_TOKEN_ENDPOINT='',
        OIDC_USERINFO_ENDPOINT='',
        OIDC_JWKS_URI='',
        OIDC_CLIENT_AUTH_METHOD='client_secret_post',
    )
    user = create_domain_and_user()
    key = ed25519.Ed25519PrivateKey.generate()
    jwks = {'keys': [jwk_from_ed25519_key(key)]}
    discovery_calls = []
    captured = {}

    def fake_get(url, headers=None, timeout=None):
        if url == app.config['OIDC_DISCOVERY_URL']:
            discovery_calls.append(url)
            return FakeResponse({
                'issuer': 'https://idp.example.test/',
                'authorization_endpoint': 'https://idp.example.test/authorize',
                'token_endpoint': 'https://idp.example.test/token',
                'jwks_uri': 'https://idp.example.test/jwks.json',
            })
        if url == 'https://idp.example.test/jwks.json':
            return FakeResponse(jwks)
        raise AssertionError(f'unexpected GET {url}')

    def fake_post(url, data=None, headers=None, auth=None, timeout=None):
        captured['data'] = data
        captured['auth'] = auth
        claims = id_token_claims(app, client, user.email, iss='https://idp.example.test/')
        return FakeResponse({'id_token': signed_eddsa_id_token(key, claims)})

    monkeypatch.setattr(oidc.requests, 'get', fake_get)
    monkeypatch.setattr(oidc.requests, 'post', fake_post)

    _, state = start_oidc_login(client, '/sso/oidc/login?target=admin')
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')

    assert rv.status_code == 302
    assert rv.headers['Location'] == '/admin'
    assert len(discovery_calls) == 1
    assert captured['auth'] is None
    assert captured['data']['client_secret'] == 'secret'


def test_oidc_rejects_unverified_email_and_respects_max_users(app, client, monkeypatch):
    configure_oidc(app, OIDC_USERINFO_ENDPOINT='', OIDC_CREATE_USER=True)
    models.db.session.add(models.Domain(name='limited.example', max_users=1))
    models.db.session.commit()
    create_domain_and_user('existing@limited.example')
    key = ed25519.Ed25519PrivateKey.generate()
    jwks = {'keys': [jwk_from_ed25519_key(key)]}
    monkeypatch.setattr(oidc.requests, 'get', lambda *args, **kwargs: FakeResponse(jwks))

    # Unverified email rejected
    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'id_token': signed_eddsa_id_token(key, id_token_claims(app, client, 'existing@limited.example', email_verified=False)),
    }))
    _, state = start_oidc_login(client)
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302 and rv.headers['Location'] == '/sso/login'

    # Domain max_users reached blocks JIT creation
    monkeypatch.setattr(oidc.requests, 'post', lambda *args, **kwargs: FakeResponse({
        'id_token': signed_eddsa_id_token(key, id_token_claims(app, client, 'second@limited.example')),
    }))
    _, state = start_oidc_login(client)
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302 and rv.headers['Location'] == '/sso/login'
    assert models.User.get('second@limited.example') is None


def test_oidc_rejects_external_url_and_supports_public_client_none(app, client, monkeypatch):
    configure_oidc(app, OIDC_USERINFO_ENDPOINT='', OIDC_CLIENT_AUTH_METHOD='none', OIDC_CLIENT_SECRET='')
    user = create_domain_and_user()
    key = ed25519.Ed25519PrivateKey.generate()
    jwks = {'keys': [jwk_from_ed25519_key(key)]}
    captured = {}

    def fake_post(url, data=None, headers=None, auth=None, timeout=None):
        captured['data'] = data
        captured['auth'] = auth
        return FakeResponse({'id_token': signed_eddsa_id_token(key, id_token_claims(app, client, user.email))})

    monkeypatch.setattr(oidc.requests, 'post', fake_post)
    monkeypatch.setattr(oidc.requests, 'get', lambda *args, **kwargs: FakeResponse(jwks))

    _, state = start_oidc_login(client, '/sso/oidc/login?url=https://evil.example/steal')
    rv = client.get(f'/sso/oidc/callback?code=abc&state={state}')
    assert rv.status_code == 302
    assert rv.headers['Location'] == '/webmail'
    assert captured['auth'] is None
    assert 'client_secret' not in captured['data']
