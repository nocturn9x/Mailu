import time

import pytest
from mailu import configuration, models, utils


def auth_headers(app, *, extra=None):
    headers = {
        'Authorization': f'Bearer {app.config["API_TOKEN"]}',
        'Content-Type': 'application/scim+json',
    }
    if extra:
        headers.update(extra)
    return headers


def create_domain(name='example.com', **kwargs):
    domain = models.Domain(name=name, **kwargs)
    models.db.session.add(domain)
    models.db.session.commit()
    return domain


def create_user(localpart='alice', domain=None, *, password='secret', displayed_name='', enabled=True):
    domain = domain or models.db.session.get(models.Domain, 'example.com') or create_domain()
    user = models.User(localpart=localpart, domain=domain, displayed_name=displayed_name, enabled=enabled)
    user.set_password(password)
    models.db.session.add(user)
    models.db.session.commit()
    return user


def create_session_and_grant(app, user):
    session = utils.MailuSession(app=app)
    session['_user_id'] = user.email
    session.save()
    grant = models.OAuth2Grant(
        user_email=user.email,
        client_id='mailu',
        scope='imap smtp',
        access_expires_at=int(time.time()) + 3600,
        refresh_expires_at=int(time.time()) + 7200,
    )
    models.db.session.add(grant)
    models.db.session.commit()
    return session.sid, grant.id


def test_discovery_endpoints(app, client):
    rv = client.get('/api/scim/v2/ServiceProviderConfig', headers=auth_headers(app))
    assert rv.status_code == 200
    assert rv.headers['Content-Type'].startswith('application/scim+json')
    spc = rv.get_json()
    assert spc['schemas'] == ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig']
    assert spc['patch']['supported'] is True
    assert spc['bulk']['supported'] is False
    assert spc['filter']['supported'] is True
    assert spc['changePassword']['supported'] is True
    assert spc['sort']['supported'] is False
    assert spc['etag']['supported'] is True
    assert spc['authenticationSchemes'][0]['type'] == 'oauthbearertoken'

    rv = client.get('/api/scim/v2/ResourceTypes', headers=auth_headers(app))
    assert rv.status_code == 200
    rts = rv.get_json()
    assert rts['totalResults'] == 1
    assert [r['id'] for r in rts['Resources']] == ['User']

    rv = client.get('/api/scim/v2/ResourceTypes/User', headers=auth_headers(app))
    assert rv.status_code == 200
    assert rv.get_json()['endpoint'] == '/Users'

    rv = client.get('/api/scim/v2/ResourceTypes/Group', headers=auth_headers(app))
    assert rv.status_code == 404
    assert rv.get_json()['schemas'] == ['urn:ietf:params:scim:api:messages:2.0:Error']

    schema_id = 'urn:ietf:params:scim:schemas:core:2.0:User'
    rv = client.get('/api/scim/v2/Schemas', headers=auth_headers(app))
    assert rv.status_code == 200
    assert [s['id'] for s in rv.get_json()['Resources']] == [schema_id]

    rv = client.get(f'/api/scim/v2/Schemas/{schema_id}', headers=auth_headers(app))
    assert rv.status_code == 200
    assert rv.get_json()['id'] == schema_id

    rv = client.get('/api/scim/v2/Schemas/urn:unknown', headers=auth_headers(app))
    assert rv.status_code == 404


def test_authentication_and_scim_errors(app, client):
    rv = client.get('/api/scim/v2/ServiceProviderConfig')
    assert rv.status_code == 401
    assert rv.headers['Content-Type'].startswith('application/scim+json')
    assert rv.get_json()['schemas'] == ['urn:ietf:params:scim:api:messages:2.0:Error']

    rv = client.get(
        '/api/scim/v2/ServiceProviderConfig',
        headers={'Authorization': 'Bearer wrong-token'},
        environ_base={'REMOTE_ADDR': '127.0.0.99'},
    )
    assert rv.status_code == 403
    assert rv.get_json()['schemas'] == ['urn:ietf:params:scim:api:messages:2.0:Error']

    # Raw token (without Bearer prefix) is also accepted by common.api_token_authorization
    rv = client.get(
        '/api/scim/v2/ServiceProviderConfig',
        headers={'Authorization': app.config['API_TOKEN']},
    )
    assert rv.status_code == 200

    # Unsupported /Groups returns SCIM 404 error
    rv = client.get('/api/scim/v2/Groups', headers=auth_headers(app))
    assert rv.status_code == 404
    assert rv.get_json()['schemas'] == ['urn:ietf:params:scim:api:messages:2.0:Error']


def test_create_get_and_authentik_adoption_flow(app, client):
    with app.app_context():
        create_domain(max_quota_bytes=500_000)

    payload = {
        'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
        'userName': 'Alice@Example.COM',
        'active': True,
        'displayName': 'Alice Example',
        'externalId': 'authentik-uid-1234',
        'emails': [{'value': 'Alice@Example.COM', 'primary': True, 'type': 'work'}],
    }
    rv = client.post('/api/scim/v2/Users', json=payload, headers=auth_headers(app))
    assert rv.status_code == 201
    assert rv.headers['ETag'].startswith('W/"')
    assert rv.headers['Location'].endswith('/api/scim/v2/Users/alice@example.com')
    data = rv.get_json()
    assert data['id'] == 'alice@example.com'
    assert data['userName'] == 'alice@example.com'
    assert data['displayName'] == 'Alice Example'
    assert data['meta']['version'] == rv.headers['ETag']
    assert 'password' not in data

    with app.app_context():
        user = models.db.session.get(models.User, 'alice@example.com')
        assert user is not None
        assert user.quota_bytes == 500_000
        assert user.displayed_name == 'Alice Example'

    # Duplicate POST returns 409 uniqueness so Authentik falls back to filter lookup
    rv = client.post('/api/scim/v2/Users', json=payload, headers=auth_headers(app))
    assert rv.status_code == 409
    assert rv.get_json()['scimType'] == 'uniqueness'

    rv = client.get(
        '/api/scim/v2/Users?filter=userName eq "Alice@Example.COM"',
        headers=auth_headers(app),
    )
    assert rv.status_code == 200
    listed = rv.get_json()
    assert listed['totalResults'] == 1
    assert listed['Resources'][0]['id'] == 'alice@example.com'

    # Conditional GET with If-None-Match returns 304
    rv = client.get(
        '/api/scim/v2/Users/alice@example.com',
        headers=auth_headers(app, extra={'If-None-Match': data['meta']['version']}),
    )
    assert rv.status_code == 304
    assert rv.headers['ETag'] == data['meta']['version']


def test_create_non_email_username_uses_primary_email_and_name_parts(app, client):
    with app.app_context():
        create_domain()

    payload = {
        'userName': 'jdoe',
        'name': {'givenName': 'Jane', 'familyName': 'Doe'},
        'emails': [
            {'value': 'secondary@example.com', 'primary': False},
            {'value': 'jane.doe@example.com', 'primary': True},
        ],
        'active': 'false',
    }
    rv = client.post('/api/scim/v2/Users', json=payload, headers=auth_headers(app))
    assert rv.status_code == 201
    data = rv.get_json()
    assert data['id'] == 'jane.doe@example.com'
    assert data['displayName'] == 'Jane Doe'
    assert data['active'] is False


def test_create_validation_and_conflicts(app, client):
    # Missing domain -> 404
    rv = client.post('/api/scim/v2/Users', json={'userName': 'ghost@missing.example'}, headers=auth_headers(app))
    assert rv.status_code == 404

    with app.app_context():
        domain = create_domain(max_users=1)
        models.db.session.add(models.Alias(localpart='taken', domain=domain, destination=['a@example.com']))
        models.db.session.commit()

    # Collision with existing alias -> 409 uniqueness
    rv = client.post('/api/scim/v2/Users', json={'userName': 'taken@example.com'}, headers=auth_headers(app))
    assert rv.status_code == 409
    assert rv.get_json()['scimType'] == 'uniqueness'

    # Domain max_users enforcement
    assert client.post('/api/scim/v2/Users', json={'userName': 'one@example.com'}, headers=auth_headers(app)).status_code == 201
    rv = client.post('/api/scim/v2/Users', json={'userName': 'two@example.com'}, headers=auth_headers(app))
    assert rv.status_code == 409
    assert rv.get_json()['scimType'] == 'uniqueness'

    # Malformed payloads
    assert client.post('/api/scim/v2/Users', data='{', content_type='application/scim+json', headers={'Authorization': f'Bearer {app.config["API_TOKEN"]}'}).status_code == 400
    assert client.post('/api/scim/v2/Users', json=[], headers=auth_headers(app)).status_code == 400
    assert client.post('/api/scim/v2/Users', json={'userName': 123}, headers=auth_headers(app)).status_code == 400
    assert client.post('/api/scim/v2/Users', json={'userName': 'not-an-email'}, headers=auth_headers(app)).status_code == 400
    assert client.post('/api/scim/v2/Users', json={'userName': 'x@example.com', 'password': {'bad': 1}}, headers=auth_headers(app)).status_code == 400


def test_list_filters_and_pagination(app, client):
    with app.app_context():
        domain = create_domain()
        create_user('alice', domain, enabled=True)
        create_user('bob', domain, enabled=False)
        create_user('carol', domain, enabled=True)

    rv = client.get('/api/scim/v2/Users?startIndex=2&count=1', headers=auth_headers(app))
    assert rv.status_code == 200
    data = rv.get_json()
    assert data['totalResults'] == 3
    assert data['startIndex'] == 2
    assert data['itemsPerPage'] == 1
    assert [u['id'] for u in data['Resources']] == ['bob@example.com']

    # Count capped to maxResults and count=0 returns totalResults with empty list
    assert client.get('/api/scim/v2/Users?count=999999', headers=auth_headers(app)).get_json()['itemsPerPage'] == 3
    zero = client.get('/api/scim/v2/Users?count=0', headers=auth_headers(app)).get_json()
    assert zero['totalResults'] == 3
    assert zero['Resources'] == []

    # Filters
    for expr, expected in [
        ('emails.value eq "bob@example.com"', ['bob@example.com']),
        ('emails[value eq "carol@example.com"]', ['carol@example.com']),
        ('(id eq "alice@example.com")', ['alice@example.com']),
        ('userName eq "not-an-email"', []),
        ('active eq false', ['bob@example.com']),
    ]:
        rv = client.get(f'/api/scim/v2/Users?filter={expr}', headers=auth_headers(app))
        assert rv.status_code == 200
        assert [u['id'] for u in rv.get_json()['Resources']] == expected

    assert client.get('/api/scim/v2/Users/not-an-email', headers=auth_headers(app)).status_code == 404
    assert client.get('/api/scim/v2/Users?startIndex=abc', headers=auth_headers(app)).status_code == 400
    rv = client.get('/api/scim/v2/Users?filter=displayName co "a"', headers=auth_headers(app))
    assert rv.status_code == 400
    assert rv.get_json()['scimType'] == 'invalidFilter'


def test_put_idempotency_updates_and_if_match(app, client):
    with app.app_context():
        user = create_user('alice', password='initial-password', displayed_name='Alice One')
        sid, grant_id = create_session_and_grant(app, user)

    rv = client.get('/api/scim/v2/Users/alice@example.com', headers=auth_headers(app))
    etag1 = rv.headers['ETag']

    # No-op PUT (even with non-email userName + matching primary email + externalId) preserves ETag & password
    noop_payload = {
        'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
        'userName': 'alice',
        'emails': [{'value': 'alice@example.com', 'primary': True}],
        'displayName': 'Alice One',
        'active': True,
        'externalId': 'ext-999',
    }
    rv = client.put('/api/scim/v2/Users/alice@example.com', json=noop_payload, headers=auth_headers(app))
    assert rv.status_code == 200
    assert rv.headers['ETag'] == etag1
    with app.app_context():
        assert models.db.session.get(models.User, 'alice@example.com').check_password('initial-password')

    # Stale If-Match returns 412 with NO mutation
    rv = client.put(
        '/api/scim/v2/Users/alice@example.com',
        json={**noop_payload, 'displayName': 'Should Not Apply'},
        headers=auth_headers(app, extra={'If-Match': 'W/"stale"'}),
    )
    assert rv.status_code == 412
    with app.app_context():
        assert models.db.session.get(models.User, 'alice@example.com').displayed_name == 'Alice One'

    # Matching If-Match updates fields, password, disables user & revokes sessions/OAuth2 grants
    rv = client.put(
        '/api/scim/v2/Users/alice@example.com',
        json={**noop_payload, 'displayName': 'Alice Two', 'active': False, 'password': 'new-password'},
        headers=auth_headers(app, extra={'If-Match': etag1}),
    )
    assert rv.status_code == 200
    assert rv.headers['ETag'] != etag1
    assert rv.get_json()['displayName'] == 'Alice Two'
    assert rv.get_json()['active'] is False

    with app.app_context():
        user = models.db.session.get(models.User, 'alice@example.com')
        assert user.enabled is False
        assert user.check_password('new-password')
        assert sid not in app.session_store.list()
        grant = models.db.session.get(models.OAuth2Grant, grant_id)
        assert grant.access_expires_at <= int(time.time())

    # Attempting to rename userName/email fails with 400 mutability
    rv = client.put(
        '/api/scim/v2/Users/alice@example.com',
        json={'userName': 'other@example.com'},
        headers=auth_headers(app),
    )
    assert rv.status_code == 400
    assert rv.get_json()['scimType'] == 'mutability'


def test_patch_operations_atomicity_and_etag(app, client):
    with app.app_context():
        create_user('carol', displayed_name='Carol Start')

    etag1 = client.get('/api/scim/v2/Users/carol@example.com', headers=auth_headers(app)).headers['ETag']

    # Stale If-Match rejected with 412
    rv = client.patch(
        '/api/scim/v2/Users/carol@example.com',
        json={'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], 'Operations': [{'op': 'replace', 'path': 'active', 'value': False}]},
        headers=auth_headers(app, extra={'If-Match': 'W/"wrong"'}),
    )
    assert rv.status_code == 412

    # Atomic failure: op 1 is valid, op 2 has unknown path -> zero mutations
    rv = client.patch(
        '/api/scim/v2/Users/carol@example.com',
        json={
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations': [
                {'op': 'replace', 'path': 'active', 'value': False},
                {'op': 'replace', 'path': 'title', 'value': 'Boss'},
            ],
        },
        headers=auth_headers(app),
    )
    assert rv.status_code == 400
    assert rv.get_json()['scimType'] == 'invalidPath'
    with app.app_context():
        assert models.db.session.get(models.User, 'carol@example.com').enabled is True

    # Pathless replace + add + remove + unchanged email/userName
    rv = client.patch(
        '/api/scim/v2/Users/carol@example.com',
        json={
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations': [
                {'op': 'replace', 'value': {'active': False, 'name': {'formatted': 'Carol Patched'}}},
                {'op': 'add', 'path': 'password', 'value': 'patched-secret'},
                {'op': 'replace', 'path': 'userName', 'value': 'carol@example.com'},
                {'op': 'replace', 'path': 'emails', 'value': [{'value': 'carol@example.com', 'primary': True}]},
            ],
        },
        headers=auth_headers(app, extra={'If-Match': '*'}),
    )
    assert rv.status_code == 200
    assert rv.headers['ETag'] != etag1
    assert rv.get_json()['active'] is False
    assert rv.get_json()['displayName'] == 'Carol Patched'
    with app.app_context():
        assert models.db.session.get(models.User, 'carol@example.com').check_password('patched-secret')

    # Remove displayName clears it; remove active fails with mutability
    rv = client.patch(
        '/api/scim/v2/Users/carol@example.com',
        json={'Operations': [{'op': 'remove', 'path': 'displayName'}]},
        headers=auth_headers(app),
    )
    assert rv.status_code == 200
    with app.app_context():
        assert models.db.session.get(models.User, 'carol@example.com').displayed_name == ''

    rv = client.patch(
        '/api/scim/v2/Users/carol@example.com',
        json={'Operations': [{'op': 'remove', 'path': 'active'}]},
        headers=auth_headers(app),
    )
    assert rv.status_code == 400
    assert rv.get_json()['scimType'] == 'mutability'

    # Invalid patch inputs
    for bad_body in [
        {'Operations': []},
        {'Operations': ['not-a-dict']},
        {'Operations': [{'op': 7, 'path': 'active', 'value': False}]},
        {'Operations': [{'op': 'replace', 'path': 'active', 'value': 'maybe'}]},
        {'Operations': [{'op': 'replace', 'path': 'password', 'value': ['bad']}]},
        {'Operations': [{'op': 'replace', 'path': 'userName', 'value': 'other@example.com'}]},
    ]:
        assert client.patch('/api/scim/v2/Users/carol@example.com', json=bad_body, headers=auth_headers(app)).status_code == 400


def test_delete_disable_vs_delete_action_and_if_match(app, client):
    with app.app_context():
        dave = create_user('dave')
        sid, grant_id = create_session_and_grant(app, dave)

    etag = client.get('/api/scim/v2/Users/dave@example.com', headers=auth_headers(app)).headers['ETag']

    # Stale If-Match fails with 412 and preserves user
    rv = client.delete(
        '/api/scim/v2/Users/dave@example.com',
        headers=auth_headers(app, extra={'If-Match': 'W/"stale"'}),
    )
    assert rv.status_code == 412
    with app.app_context():
        assert models.db.session.get(models.User, 'dave@example.com').enabled is True

    # Default SCIM_DELETE_ACTION='disable' disables account & revokes sessions/OAuth2 grants
    rv = client.delete(
        '/api/scim/v2/Users/dave@example.com',
        headers=auth_headers(app, extra={'If-Match': etag}),
    )
    assert rv.status_code == 204
    with app.app_context():
        user = models.db.session.get(models.User, 'dave@example.com')
        assert user is not None
        assert user.enabled is False
        assert sid not in app.session_store.list()
        assert models.db.session.get(models.OAuth2Grant, grant_id).access_expires_at <= int(time.time())

    # SCIM_DELETE_ACTION='delete' deletes row and frees the address for reuse
    app.config['SCIM_DELETE_ACTION'] = 'delete'
    rv = client.delete('/api/scim/v2/Users/dave@example.com', headers=auth_headers(app))
    assert rv.status_code == 204
    with app.app_context():
        assert models.db.session.get(models.User, 'dave@example.com') is None

    # Deleting a nonexistent user returns 404
    rv = client.delete('/api/scim/v2/Users/dave@example.com', headers=auth_headers(app))
    assert rv.status_code == 404

    # Address is free to recreate immediately
    rv = client.post('/api/scim/v2/Users', json={'userName': 'dave@example.com'}, headers=auth_headers(app))
    assert rv.status_code == 201


def test_invalid_scim_delete_action_config_rejected(monkeypatch):
    monkeypatch.setenv('SCIM_DELETE_ACTION', 'archive')
    config = configuration.ConfigManager()
    dummy_app = type('DummyApp', (), {'config': {}})()
    with pytest.raises(ValueError, match='SCIM_DELETE_ACTION'):
        config.init_app(dummy_app)
