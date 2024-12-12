import base64
import hashlib
import re
import secrets
import time
import urllib.parse

from flask import (
    session, request, current_app, redirect, Blueprint, abort
)
import requests
import requests.auth
import jwt
from opentelemetry import trace
from opentelemetry.semconv._incubating.attributes import user_attributes


from . import spanattrs


tracer = trace.get_tracer(__name__)
blueprint = Blueprint('oidc', __name__)


@blueprint.get('/login')
def login():
    span = trace.get_current_span()
    next_path = urllib.parse.unquote_plus(
        request.args.get('next', '/')
    )
    span.set_attribute('next_path', next_path)

    if urllib.parse.urlparse(next_path).netloc:
        # all redirects should be relative here
        span.set_attribute(spanattrs.MALICIOUS_REDIRECT, next_path)
        abort(400)

    state, state_sha256 = s256_pair()
    code_verifier, code_challenge = s256_pair()

    login_url = current_app.config['AUTHORIZATION_SERVER_LOGIN_URL']
    client_id = current_app.config['CLIENT_ID']
    urlsafe_redirect_uri = urllib.parse.quote_plus(
        current_app.config['REDIRECT_URL']
    )
    auth_request = f'{login_url}?client_id={client_id}' \
        '&response_type=code' \
        '&code_challenge_method=S256' \
        f'&code_challenge={code_challenge}' \
        f'&state={state_sha256}' \
        f'&redirect_uri={urlsafe_redirect_uri}'

    session['state'] = state
    session['code_verifier'] = code_verifier
    session['next_path'] = next_path

    return redirect(auth_request)


def is_urlsafe_32_byte_token(token):
    return bool(re.match(r'^[A-Za-z0-9\-_]{43}$', token))


@tracer.start_as_current_span('get_signing_key')
def get_signing_key(token):
    jwks_client = current_app.extensions['oidc'].jwks_client
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return signing_key.key


@tracer.start_as_current_span('decode_jwt')
def decode(token):
    signing_key = get_signing_key(token)
    return jwt.decode(token, signing_key.key,
                      audience=current_app.config['CLIENT_ID'],
                      issuer=current_app.config['ISSUER'],
                      algorithms=["RS256"], options={'require': ['sub']})


@blueprint.get('/oidc')
def oidc():

    state_param = request.args.get('state', '')

    span = trace.get_current_span()
    if not is_urlsafe_32_byte_token(state_param):
        span.set_attribute(spanattrs.INPUT_VALIDATION_FAIL, 'state')
        abort(400)

    state_cookie = session.pop('state', '')
    if not is_urlsafe_32_byte_token(state_cookie):
        span.set_attribute(spanattrs.INPUT_VALIDATION_FAIL, 'state_cookie')
        abort(400)

    if not s256_match(state_cookie, state_param):
        span.set_attribute(spanattrs.MALICIOUS_CSRF, True)
        abort(400)

    code_param = request.args.get('code')
    if not code_param:
        span.set_attribute(spanattrs.INPUT_VALIDATION_FAIL, 'code')
        abort(400)

    code_verifier = session.pop('code_verifier', '')
    if not is_urlsafe_32_byte_token(code_verifier):
        span.set_attribute(spanattrs.INPUT_VALIDATION_FAIL, 'code_verifer')
        abort(400)

    next_path = urllib.parse.unquote_plus(
        session.pop('next_path', '/')
    )
    span.set_attribute(spanattrs.NEXT_PATH, next_path)
    if urllib.parse.urlparse(next_path).netloc:
        # all redirects should be relative here
        span.set_attribute(spanattrs.MALICIOUS_REDIRECT, next_path)
        abort(400)

    client_id = current_app.config['CLIENT_ID']
    data = {
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'redirect_uri': current_app.config['REDIRECT_URL'],
        'code': code_param,
        'state': state_param,
        'code_verifier': code_verifier
    }

    client_secret = current_app.config['CLIENT_SECRET']
    token_endpoint = current_app.config['TOKEN_ENDPOINT']
    try:
        response = requests.post(
            token_endpoint,
            data=data,
            auth=requests.auth.HTTPBasicAuth(
                client_id,
                client_secret
            )
        )

        response.raise_for_status()
        auth_token = response.json()

        id_token = auth_token['id_token']
        claims = decode(id_token)
    except requests.exceptions.HTTPError as e:
        span.record_exception(e)
        span.set_attribute(spanattrs.OIDC_TOKEN_ENDPOINT_FAILURE, str(e))
        abort(401)
    except jwt.exceptions.PyJWTError as e:
        span.record_exception(e)
        span.set_attribute(spanattrs.OIDC_TOKEN_DECODE_FAILURE, str(e))
        abort(401)
    except Exception as e:
        span.record_exception(e)
        span.set_attribute(spanattrs.OIDC_TOKEN_UNKNOWN_FAILURE, str(e))
        abort(401)

    session['oidc_user_id'] = claims['sub']
    email_claim = current_app.config.get('EMAIL_CLAIM', 'email')
    session['oidc_email'] = claims.get(email_claim, '')
    groups_claim = current_app.config.get('GROUPS_CLAIM', 'groups')
    session['oidc_groups'] = claims.get(groups_claim, [])
    name_claim = current_app.config.get('NAME_CLAIM', 'name')
    session['oidc_name'] = claims.get(name_claim, '')
    session['oidc_auth_at'] = int(time.time())

    span.add_event(spanattrs.USER_AUTHENTICATED, {
        user_attributes.USER_ID: claims['sub'],
        user_attributes.USER_EMAIL: claims.get(email_claim, ''),
        user_attributes.USER_ROLES: claims.get(groups_claim, []),
        user_attributes.USER_FULL_NAME: claims.get(name_claim, '')
    })
    return redirect(next_path)


@blueprint.get('/logout')
def logout():
    session.clear()

    client_id = current_app.config['CLIENT_ID']
    urlsafe_redirect_uri = urllib.parse.quote_plus(
        current_app.config['LOGOUT_REDIRECT_URL']
    )
    logout_url = current_app.config['AUTHORIZATION_SERVER_LOGOUT_URL']
    logout_request = f'{logout_url}?client_id={client_id}' \
        f'&logout_uri={urlsafe_redirect_uri}'

    return redirect(logout_request)


def s256_hash(s):
    h = hashlib.sha256(s.encode('ascii')).digest()
    return base64.urlsafe_b64encode(h).rstrip(b'=').decode('ascii')


def s256_pair():
    s = secrets.token_urlsafe(nbytes=32)
    return s, s256_hash(s)


def s256_match(s, hash):
    return s256_hash(s) == hash
