"""Minimal Users-only SCIM 2.0 (RFC 7643 / RFC 7644) provisioning API."""

import hashlib
import json
import re
import secrets
import urllib.parse

import flask
import sqlalchemy
from sqlalchemy.exc import IntegrityError, SQLAlchemyError, StatementError
from werkzeug.exceptions import HTTPException
from werkzeug.http import parse_etags, unquote_etag

from . import common
from .. import models, oauth2, utils

SCIM_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User'
SCIM_LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'
SCIM_PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
SCIM_ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error'
SCIM_SPC_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'
SCIM_RESOURCE_TYPE_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ResourceType'
SCIM_SCHEMA_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Schema'

SCIM_MAX_RESULTS = 200
MAX_DISPLAY_NAME_LENGTH = 160

_STRING_EQ_FILTER = re.compile(
    r'^\s*(userName|id|emails\.value)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$',
    re.IGNORECASE,
)
_EMAILS_FILTER = re.compile(
    r'^\s*emails\s*\[\s*value\s+eq\s+"((?:[^"\\]|\\.)*)"\s*\]\s*$',
    re.IGNORECASE,
)
_ACTIVE_EQ_FILTER = re.compile(r'^\s*active\s+eq\s+(true|false)\s*$', re.IGNORECASE)
_EMAILS_PATCH_PATH = re.compile(r'^emails(?:\[[^\]]+\])?\.value$', re.IGNORECASE)

blueprint = flask.Blueprint('scim', __name__)


def _base_url():
    web_api_root = flask.current_app.config.get('WEB_API') or '/api'
    return flask.request.url_root.rstrip('/') + web_api_root.rstrip('/') + '/scim/v2'


def _resource_location(resource, resource_id):
    return f'{_base_url()}/{resource}/{urllib.parse.quote(resource_id, safe="@._+-:")}'


def _scim_response(payload, status=200, *, etag=None, location=None):
    response = flask.jsonify(payload)
    response.status_code = status
    response.headers['Content-Type'] = 'application/scim+json'
    if etag:
        response.headers['ETag'] = etag
    if location:
        response.headers['Content-Location'] = location
        if status == 201:
            response.headers['Location'] = location
    return response


def _list_response(resources, *, total=None, start_index=1):
    return _scim_response({
        'schemas': [SCIM_LIST_SCHEMA],
        'totalResults': len(resources) if total is None else total,
        'startIndex': start_index,
        'itemsPerPage': len(resources),
        'Resources': resources,
    })


def _scim_error(status, detail, scim_type=None):
    payload = {'schemas': [SCIM_ERROR_SCHEMA], 'status': str(status), 'detail': detail}
    if scim_type:
        payload['scimType'] = scim_type
    return _scim_response(payload, status)


@blueprint.before_request
def authorize():
    if flask.request.method == 'OPTIONS':
        return None

    @common.api_token_authorization
    def _authorized():
        return None

    return _authorized()


@blueprint.errorhandler(HTTPException)
def handle_http_error(error):
    data = getattr(error, 'data', None)
    detail = data.get('message') if isinstance(data, dict) and isinstance(data.get('message'), str) else None
    return _scim_error(error.code or 500, detail or getattr(error, 'description', None) or str(error))


@blueprint.errorhandler(SQLAlchemyError)
def handle_database_error(_error):
    models.db.session.rollback()
    flask.current_app.logger.exception('Unhandled SCIM database error')
    return _scim_error(500, 'The SCIM database operation failed')


def _payload():
    data = flask.request.get_json(silent=True)
    if data is None:
        if flask.request.get_data(cache=True).strip():
            return None, _scim_error(400, 'Request body must be valid JSON', 'invalidSyntax')
        return {}, None
    if not isinstance(data, dict):
        return None, _scim_error(400, 'Request body must be a JSON object', 'invalidSyntax')
    return data, None


def _parse_int_param(value, default, *, minimum=0, maximum=None):
    if value is None:
        return default
    try:
        parsed = max(int(value), minimum)
    except (TypeError, ValueError):
        return None
    return min(parsed, maximum) if maximum is not None else parsed


def _user_etag(user):
    state = (
        user.email,
        bool(user.enabled),
        user.displayed_name or '',
        user.quota_bytes,
        user.password or '',
        user.created_at.isoformat() if user.created_at else '',
        user.updated_at.isoformat() if user.updated_at else '',
    )
    digest = hashlib.sha256(json.dumps(state, separators=(',', ':')).encode('utf-8')).hexdigest()[:32]
    return f'W/"{digest}"'


def _etag_matches(header_value, current_etag):
    if header_value.strip() == '*':
        return True
    candidates = parse_etags(header_value)
    current_tag, _ = unquote_etag(current_etag)
    return candidates.star_tag or candidates.contains_weak(current_tag)


def _check_if_match(user):
    header_value = flask.request.headers.get('If-Match')
    if header_value is None or _etag_matches(header_value, _user_etag(user)):
        return None
    return _scim_error(412, 'If-Match precondition failed')


def _make_user_resource(user):
    email = user.email
    display_name = user.displayed_name or email
    meta = {
        'resourceType': 'User',
        'location': _resource_location('Users', email),
        'version': _user_etag(user),
    }
    if user.created_at:
        meta['created'] = f'{user.created_at.isoformat()}T00:00:00Z'
    if last_modified := (user.updated_at or user.created_at):
        meta['lastModified'] = f'{last_modified.isoformat()}T00:00:00Z'
    return {
        'schemas': [SCIM_USER_SCHEMA],
        'id': email,
        'userName': email,
        'active': bool(user.enabled),
        'displayName': display_name,
        'name': {'formatted': display_name},
        'emails': [{'value': email, 'primary': True, 'type': 'work'}],
        'meta': meta,
    }


def _user_response(user, status=200):
    payload = _make_user_resource(user)
    meta = payload['meta']
    return _scim_response(payload, status=status, etag=meta['version'], location=meta['location'])


def _get_user(user_id):
    normalized = user_id.strip().lower()
    if not utils.is_valid_email(normalized):
        return None
    try:
        return models.db.session.get(models.User, normalized)
    except StatementError:
        return None


def _active_value(value):
    if isinstance(value, bool):
        return value, None
    if isinstance(value, str) and value.strip().lower() in ('true', 'false'):
        return value.strip().lower() == 'true', None
    return None, _scim_error(400, 'active must be a boolean', 'invalidValue')


def _password_value(value, *, required=False):
    if value in (None, ''):
        if required:
            return None, _scim_error(400, 'password must be a non-empty string', 'invalidValue')
        return None, None
    if not isinstance(value, str):
        return None, _scim_error(400, 'password must be a string', 'invalidValue')
    return value, None


def _validate_display_name(value):
    if value is None:
        return '', None
    if not isinstance(value, str):
        return None, _scim_error(400, 'displayName must be a string', 'invalidValue')
    cleaned = value.strip()
    if len(cleaned) > MAX_DISPLAY_NAME_LENGTH:
        return None, _scim_error(400, f'displayName must be at most {MAX_DISPLAY_NAME_LENGTH} characters', 'invalidValue')
    return cleaned, None


def _extract_name_display(name):
    if name is None:
        return '', None
    if not isinstance(name, dict):
        return None, _scim_error(400, 'name must be an object', 'invalidValue')
    formatted = name.get('formatted')
    if formatted is not None:
        if not isinstance(formatted, str):
            return None, _scim_error(400, 'name.formatted must be a string', 'invalidValue')
        if formatted.strip():
            return _validate_display_name(formatted)
    parts = []
    for key in ('givenName', 'familyName'):
        part = name.get(key)
        if part is not None:
            if not isinstance(part, str):
                return None, _scim_error(400, f'name.{key} must be a string', 'invalidValue')
            if part.strip():
                parts.append(part.strip())
    return _validate_display_name(' '.join(parts))


def _extract_email_from_list(emails):
    if emails is None:
        return '', None
    if not isinstance(emails, list):
        return None, _scim_error(400, 'emails must be a list', 'invalidValue')
    first_email = primary_email = ''
    for item in emails:
        if not isinstance(item, dict):
            return None, _scim_error(400, 'emails entries must be objects', 'invalidValue')
        value = item.get('value')
        if value in (None, ''):
            continue
        if not isinstance(value, str):
            return None, _scim_error(400, 'email values must be strings', 'invalidValue')
        if cleaned := value.strip().lower():
            first_email = first_email or cleaned
            if item.get('primary') is True and not primary_email:
                primary_email = cleaned
    return primary_email or first_email, None


def _extract_user_email(data):
    user_name = data.get('userName')
    normalized_username = ''
    if user_name not in (None, ''):
        if not isinstance(user_name, str):
            return None, _scim_error(400, 'userName must be a string', 'invalidValue')
        normalized_username = user_name.strip().lower()
    list_email = ''
    if data.get('emails') is not None:
        list_email, error = _extract_email_from_list(data['emails'])
        if error:
            return None, error
    return (normalized_username if '@' in normalized_username else (list_email or normalized_username)), None


def _parse_user_attributes(data):
    active = True
    if 'active' in data:
        active, error = _active_value(data['active'])
        if error:
            return None, error
    display_name = ''
    if data.get('displayName') is not None:
        display_name, error = _validate_display_name(data['displayName'])
        if error:
            return None, error
    if not display_name and data.get('name') is not None:
        display_name, error = _extract_name_display(data['name'])
        if error:
            return None, error
    password, error = _password_value(data.get('password'))
    if error:
        return None, error
    return {'active': active, 'display_name': display_name, 'password': password}, None


def _normalize_patch_path(raw_path):
    if raw_path is None:
        return '', None
    if not isinstance(raw_path, str):
        return None, _scim_error(400, 'Patch path must be a string', 'invalidPath')
    path = raw_path.strip().lower()
    prefix = f'{SCIM_USER_SCHEMA.lower()}:'
    return (path[len(prefix):] if path.startswith(prefix) else path), None


def _apply_patch_attribute(user, path, value, state):
    if path == 'active':
        active, error = _active_value(value)
        if error:
            return error
        state['active'] = active
        return None
    if path in ('displayname', 'name.formatted', 'name'):
        display_name, error = _extract_name_display(value) if path == 'name' else _validate_display_name(value)
        if error:
            return error
        state['display_name'] = display_name
        state['display_name_explicit'] = True
        return None
    if path in ('name.givenname', 'name.familyname'):
        if value is not None and not isinstance(value, str):
            return _scim_error(400, f'{path} must be a string', 'invalidValue')
        state[path] = (value or '').strip()
        return None
    if path == 'password':
        password, error = _password_value(value, required=True)
        if error:
            return error
        state['password'] = password
        return None
    if path == 'username':
        if not isinstance(value, str) or not value.strip():
            return _scim_error(400, 'userName must be a non-empty string', 'invalidValue')
        cleaned = value.strip().lower()
        if '@' in cleaned and cleaned != user.email:
            return _scim_error(400, 'Changing userName/email is not supported', 'mutability')
        return None
    if path == 'emails':
        list_email, error = _extract_email_from_list(value)
        if error:
            return error
        if list_email and list_email != user.email:
            return _scim_error(400, 'Changing userName/email is not supported', 'mutability')
        return None
    if _EMAILS_PATCH_PATH.match(path):
        if not isinstance(value, str) or not value.strip():
            return _scim_error(400, 'email value must be a non-empty string', 'invalidValue')
        if value.strip().lower() != user.email:
            return _scim_error(400, 'Changing userName/email is not supported', 'mutability')
        return None
    if path == 'externalid':
        if value is not None and not isinstance(value, str):
            return _scim_error(400, 'externalId must be a string', 'invalidValue')
        return None
    return _scim_error(400, f'Patch path {path!r} is not supported', 'invalidPath')


def _compute_patch_state(user, data):
    if 'schemas' in data:
        schemas = data['schemas']
        if not isinstance(schemas, list) or SCIM_PATCH_SCHEMA not in schemas:
            return None, _scim_error(400, f'schemas must include {SCIM_PATCH_SCHEMA}', 'invalidSyntax')

    operations = data['Operations'] if 'Operations' in data else data.get('operations')
    if not isinstance(operations, list):
        return None, _scim_error(400, 'Operations must be a list', 'invalidSyntax')
    if not operations:
        return None, _scim_error(400, 'Operations must not be empty', 'invalidValue')

    state = {'active': bool(user.enabled), 'display_name': user.displayed_name, 'display_name_explicit': False, 'password': None}
    for operation in operations:
        if not isinstance(operation, dict):
            return None, _scim_error(400, 'Patch operations must be objects', 'invalidSyntax')
        raw_op = operation.get('op')
        if not isinstance(raw_op, str):
            return None, _scim_error(400, 'Patch op must be a string', 'invalidSyntax')
        op = raw_op.strip().lower()
        if op not in ('add', 'replace', 'remove'):
            return None, _scim_error(400, f'Patch operation {op!r} is not supported', 'invalidValue')
        path, error = _normalize_patch_path(operation.get('path'))
        if error:
            return None, error

        if op == 'remove':
            if not path:
                return None, _scim_error(400, 'remove operation requires a path', 'noTarget')
            if path in ('displayname', 'name', 'name.formatted', 'name.givenname', 'name.familyname'):
                state['display_name'] = ''
                state['display_name_explicit'] = True
            elif path == 'externalid':
                pass
            elif path in ('username', 'id', 'emails', 'active', 'password') or _EMAILS_PATCH_PATH.match(path):
                return None, _scim_error(400, f'Attribute {path!r} cannot be removed', 'mutability')
            else:
                return None, _scim_error(400, f'Patch path {path!r} is not supported', 'invalidPath')
            continue

        value = operation.get('value')
        if not path:
            if not isinstance(value, dict) or not value:
                return None, _scim_error(400, 'Patch operation without path requires an object value', 'invalidValue')
            for key, item_value in value.items():
                sub_path, error = _normalize_patch_path(key)
                if error or (error := _apply_patch_attribute(user, sub_path, item_value, state)):
                    return None, error
        elif error := _apply_patch_attribute(user, path, value, state):
            return None, error

    if not state['display_name_explicit'] and ('name.givenname' in state or 'name.familyname' in state):
        combined, error = _validate_display_name(
            ' '.join(p for p in (state.get('name.givenname', ''), state.get('name.familyname', '')) if p)
        )
        if error:
            return None, error
        state['display_name'] = combined
    return state, None


def _apply_user_updates(user, *, active, display_name, password):
    changed = disabled_now = False
    if active != bool(user.enabled):
        disabled_now = bool(user.enabled) and not active
        user.enabled = active
        changed = True
    if display_name != user.displayed_name:
        user.displayed_name = display_name
        changed = True
    if password:
        user.set_password(password)
        changed = True
    if not changed:
        return
    if disabled_now and not password:
        oauth2.force_user_reauthentication(user, 'user disabled')
    models.db.session.add(user)
    models.db.session.commit()
    if disabled_now:
        utils.MailuSessionExtension.prune_sessions(uid=user.email)


def _apply_user_filter(query, filter_expr):
    expr = filter_expr.strip()
    if expr.startswith('(') and expr.endswith(')'):
        expr = expr[1:-1].strip()
    if match := (_STRING_EQ_FILTER.match(expr) or _EMAILS_FILTER.match(expr)):
        raw_value = match.group(match.lastindex).replace('\\"', '"').replace('\\\\', '\\').strip().lower()
        return query.filter(sqlalchemy.func.lower(models.User._email) == raw_value), None
    if match := _ACTIVE_EQ_FILTER.match(expr):
        return query.filter(models.User.enabled.is_(match.group(1).lower() == 'true')), None
    return None, _scim_error(
        400,
        'Supported filters are userName eq, id eq, emails.value eq, emails[value eq], and active eq',
        'invalidFilter',
    )


def _user_resource_type():
    return {
        'schemas': [SCIM_RESOURCE_TYPE_SCHEMA],
        'id': 'User',
        'name': 'User',
        'endpoint': '/Users',
        'description': 'Mailu user account',
        'schema': SCIM_USER_SCHEMA,
        'meta': {'resourceType': 'ResourceType', 'location': _resource_location('ResourceTypes', 'User')},
    }


def _user_schema_definition():
    return {
        'schemas': [SCIM_SCHEMA_SCHEMA],
        'id': SCIM_USER_SCHEMA,
        'name': 'User',
        'description': 'Mailu SCIM 2.0 User resource',
        'attributes': [
            {'name': 'userName', 'type': 'string', 'multiValued': False, 'required': True, 'caseExact': False, 'mutability': 'immutable', 'returned': 'default', 'uniqueness': 'server'},
            {'name': 'displayName', 'type': 'string', 'multiValued': False, 'required': False, 'caseExact': False, 'mutability': 'readWrite', 'returned': 'default', 'uniqueness': 'none'},
            {
                'name': 'name', 'type': 'complex', 'multiValued': False, 'required': False, 'mutability': 'readWrite', 'returned': 'default',
                'subAttributes': [
                    {'name': 'formatted', 'type': 'string', 'multiValued': False, 'mutability': 'readWrite'},
                    {'name': 'givenName', 'type': 'string', 'multiValued': False, 'mutability': 'writeOnly'},
                    {'name': 'familyName', 'type': 'string', 'multiValued': False, 'mutability': 'writeOnly'},
                ],
            },
            {
                'name': 'emails', 'type': 'complex', 'multiValued': True, 'required': False, 'mutability': 'immutable', 'returned': 'default',
                'subAttributes': [
                    {'name': 'value', 'type': 'string', 'multiValued': False, 'mutability': 'immutable'},
                    {'name': 'type', 'type': 'string', 'multiValued': False, 'mutability': 'readOnly'},
                    {'name': 'primary', 'type': 'boolean', 'multiValued': False, 'mutability': 'readOnly'},
                ],
            },
            {'name': 'active', 'type': 'boolean', 'multiValued': False, 'required': False, 'mutability': 'readWrite', 'returned': 'default'},
            {'name': 'password', 'type': 'string', 'multiValued': False, 'required': False, 'mutability': 'writeOnly', 'returned': 'never'},
        ],
        'meta': {'resourceType': 'Schema', 'location': _resource_location('Schemas', SCIM_USER_SCHEMA)},
    }


@blueprint.route('/ServiceProviderConfig', methods=['GET'])
def service_provider_config():
    return _scim_response({
        'schemas': [SCIM_SPC_SCHEMA],
        'documentationUri': 'https://mailu.io/master/api.html',
        'patch': {'supported': True},
        'bulk': {'supported': False, 'maxOperations': 0, 'maxPayloadSize': 0},
        'filter': {'supported': True, 'maxResults': SCIM_MAX_RESULTS},
        'changePassword': {'supported': True},
        'sort': {'supported': False},
        'etag': {'supported': True},
        'authenticationSchemes': [{
            'type': 'oauthbearertoken',
            'name': 'OAuth Bearer Token',
            'description': 'Authentication scheme using the Mailu API_TOKEN bearer token',
            'primary': True,
        }],
        'meta': {'resourceType': 'ServiceProviderConfig', 'location': f'{_base_url()}/ServiceProviderConfig'},
    })


@blueprint.route('/ResourceTypes', methods=['GET'])
def list_resource_types():
    return _list_response([_user_resource_type()])


@blueprint.route('/ResourceTypes/<resource_id>', methods=['GET'])
def get_resource_type(resource_id):
    if resource_id.lower() != 'user':
        return _scim_error(404, f'ResourceType {resource_id} cannot be found')
    return _scim_response(_user_resource_type())


@blueprint.route('/Schemas', methods=['GET'])
def list_schemas():
    return _list_response([_user_schema_definition()])


@blueprint.route('/Schemas/<path:schema_id>', methods=['GET'])
def get_schema(schema_id):
    if schema_id != SCIM_USER_SCHEMA:
        return _scim_error(404, f'Schema {schema_id} cannot be found')
    return _scim_response(_user_schema_definition())


@blueprint.route('/Users', methods=['GET'])
def list_users():
    start_index = _parse_int_param(flask.request.args.get('startIndex'), 1, minimum=1)
    count = _parse_int_param(flask.request.args.get('count'), 100, minimum=0, maximum=SCIM_MAX_RESULTS)
    if start_index is None or count is None:
        return _scim_error(400, 'startIndex and count must be integers', 'invalidValue')

    query = models.User.query.order_by(models.User._email)
    if filter_expr := flask.request.args.get('filter'):
        query, error = _apply_user_filter(query, filter_expr)
        if error:
            return error

    total = query.count()
    users = query.offset(start_index - 1).limit(count).all() if count else []
    return _list_response([_make_user_resource(u) for u in users], total=total, start_index=start_index)


@blueprint.route('/Users', methods=['POST'])
def create_user():
    data, error = _payload()
    if error:
        return error
    email, error = _extract_user_email(data)
    if error:
        return error
    if not email:
        return _scim_error(400, 'userName or emails[0].value is required', 'invalidValue')
    if not utils.is_valid_email(email):
        return _scim_error(400, f'{email!r} is not a valid email address', 'invalidValue')
    attrs, error = _parse_user_attributes(data)
    if error:
        return error
    if _get_user(email):
        return _scim_error(409, f'User {email} already exists', 'uniqueness')

    localpart, domain_name = email.rsplit('@', 1)
    domain = models.db.session.get(models.Domain, domain_name)
    if not domain:
        return _scim_error(404, f'Domain {domain_name} does not exist')
    if domain.max_users != -1 and len(domain.users) >= domain.max_users:
        return _scim_error(409, f'Too many users for domain {domain_name}', 'uniqueness')
    if models.Alias.query.filter(sqlalchemy.func.lower(models.Alias._email) == email).first():
        return _scim_error(409, f'Address {email} is already used by an alias', 'uniqueness')

    default_quota = int(flask.current_app.config.get('DEFAULT_QUOTA', 10**9))
    quota_bytes = min(default_quota, domain.max_quota_bytes) if domain.max_quota_bytes else default_quota
    user = models.User(
        localpart=localpart,
        domain=domain,
        enabled=attrs['active'],
        displayed_name=attrs['display_name'],
        quota_bytes=quota_bytes,
    )
    user.set_password(attrs['password'] or secrets.token_urlsafe(32))
    models.db.session.add(user)
    try:
        models.db.session.commit()
    except IntegrityError:
        models.db.session.rollback()
        return _scim_error(409, f'User {email} already exists', 'uniqueness')
    return _user_response(user, status=201)


@blueprint.route('/Users/<path:user_id>', methods=['GET'])
def get_user(user_id):
    user = _get_user(user_id)
    if not user:
        return _scim_error(404, f'User {user_id} cannot be found')
    current_etag = _user_etag(user)
    if_none_match = flask.request.headers.get('If-None-Match')
    if if_none_match is not None and _etag_matches(if_none_match, current_etag):
        response = flask.Response(status=304)
        response.headers['ETag'] = current_etag
        return response
    return _user_response(user)


@blueprint.route('/Users/<path:user_id>', methods=['PUT'])
def replace_user(user_id):
    user = _get_user(user_id)
    if not user:
        return _scim_error(404, f'User {user_id} cannot be found')
    if error := _check_if_match(user):
        return error
    data, error = _payload()
    if error:
        return error
    new_email, error = _extract_user_email(data)
    if error:
        return error
    if new_email and new_email != user.email:
        return _scim_error(400, 'Changing userName/email is not supported', 'mutability')
    attrs, error = _parse_user_attributes(data)
    if error:
        return error
    _apply_user_updates(user, **attrs)
    return _user_response(user)


@blueprint.route('/Users/<path:user_id>', methods=['PATCH'])
def patch_user(user_id):
    user = _get_user(user_id)
    if not user:
        return _scim_error(404, f'User {user_id} cannot be found')
    if error := _check_if_match(user):
        return error
    data, error = _payload()
    if error:
        return error
    state, error = _compute_patch_state(user, data)
    if error:
        return error
    _apply_user_updates(user, active=state['active'], display_name=state['display_name'], password=state['password'])
    return _user_response(user)


@blueprint.route('/Users/<path:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = _get_user(user_id)
    if not user:
        return _scim_error(404, f'User {user_id} cannot be found')
    if error := _check_if_match(user):
        return error
    email = user.email
    action = (flask.current_app.config.get('SCIM_DELETE_ACTION') or 'disable').strip().lower()
    if action == 'delete':
        models.db.session.delete(user)
        models.db.session.commit()
        utils.MailuSessionExtension.prune_sessions(uid=email)
    else:
        if user.enabled or user.oauth2_grants:
            user.enabled = False
            oauth2.force_user_reauthentication(user, 'user disabled')
            models.db.session.add(user)
            models.db.session.commit()
        utils.MailuSessionExtension.prune_sessions(uid=email)
    return '', 204


@blueprint.route('/<path:unknown>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def unsupported_endpoint(unknown):
    return _scim_error(404, f'SCIM endpoint /{unknown} is not supported')
