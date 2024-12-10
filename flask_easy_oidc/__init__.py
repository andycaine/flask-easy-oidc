import base64
import enum
import hashlib
import re
import secrets
import time
import urllib.parse

from flask import (
    session, request, Flask, current_app, redirect, Blueprint, abort
)
import requests
import requests.auth
import jwt
from opentelemetry import trace


__all__ = ['create_app', 'OidcExtension', 'blueprint']

tracer = trace.get_tracer(__name__)
OTEL_NAMESPACE = 'com.andycaine.flask_easy_oidc'
NEXT_PATH = f'{OTEL_NAMESPACE}.next_path'
MALICIOUS_REDIRECT = f'{OTEL_NAMESPACE}.malicious_redirect'
INPUT_VALIDATION_FAIL = f'{OTEL_NAMESPACE}.input_validation_fail'
MALICIOUS_CSRF = f'{OTEL_NAMESPACE}.malicious_csrf'
OIDC_TOKEN_ENDPOINT_FAILURE = f'{OTEL_NAMESPACE}.oidc_token_endpoint_failure'
OIDC_TOKEN_DECODE_FAILURE = f'{OTEL_NAMESPACE}.oidc_token_decode_failure'
OIDC_TOKEN_UNKNOWN_FAILURE = f'{OTEL_NAMESPACE}.oidc_token_unknown_failure'


def create_app():
    app = Flask(__name__)
    app.config.from_prefixed_env(prefix='OIDC')

    OidcExtension(app=app, url_prefix='/auth')
    return app


blueprint = Blueprint('oidc', __name__)


def _set_span_attr(k, v):
    trace.get_current_span().set_attribute(k, v)


@blueprint.get('/login')
def login():
    next_path = urllib.parse.unquote_plus(
        request.args.get('next', '/')
    )
    _set_span_attr('next_path', next_path)

    if urllib.parse.urlparse(next_path).netloc:
        # all redirects should be relative here
        _set_span_attr(MALICIOUS_REDIRECT, next_path)
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


@blueprint.get('/oidc')
def oidc():

    def decode(token):
        jwks_client = current_app.extensions['oidc'].jwks_client
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        return jwt.decode(token, signing_key.key,
                          audience=current_app.config['CLIENT_ID'],
                          issuer=current_app.config['ISSUER'],
                          algorithms=["RS256"], options={'require': ['sub']})

    state_param = request.args.get('state', '')

    span = trace.get_current_span()
    if not is_urlsafe_32_byte_token(state_param):
        span.set_attribute(INPUT_VALIDATION_FAIL, 'state')
        abort(400)

    state_cookie = session.pop('state', '')
    if not is_urlsafe_32_byte_token(state_cookie):
        span.set_attribute(INPUT_VALIDATION_FAIL, 'state_cookie')
        abort(400)

    if not s256_match(state_cookie, state_param):
        span.set_attribute('malicious_csrf', True)
        abort(400)

    code_param = request.args.get('code')
    if not code_param:
        span.set_attribute(INPUT_VALIDATION_FAIL, 'code')
        abort(400)

    code_verifier = session.pop('code_verifier', '')
    if not is_urlsafe_32_byte_token(code_verifier):
        span.set_attribute(INPUT_VALIDATION_FAIL, 'code_verifer')
        abort(400)

    next_path = urllib.parse.unquote_plus(
        session.pop('next_path', '/')
    )
    span.set_attribute(NEXT_PATH, next_path)
    if urllib.parse.urlparse(next_path).netloc:
        # all redirects should be relative here
        span.set_attribute(MALICIOUS_REDIRECT, next_path)
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
        span.set_attribute(OIDC_TOKEN_ENDPOINT_FAILURE, str(e))
        abort(401)
    except jwt.exceptions.PyJWTError as e:
        span.record_exception(e)
        span.set_attribute(OIDC_TOKEN_DECODE_FAILURE, str(e))
        abort(401)
    except Exception as e:
        span.record_exception(e)
        span.set_attribute(OIDC_TOKEN_UNKNOWN_FAILURE, str(e))
        abort(401)

    session['oidc_user_id'] = claims['sub']
    span.set_attribute('user.id', claims['sub'])
    email_claim = current_app.config.get('EMAIL_CLAIM', 'email')
    session['oidc_email'] = claims.get(email_claim, '')
    groups_claim = current_app.config.get('GROUPS_CLAIM', 'groups')
    session['oidc_groups'] = claims.get(groups_claim, [])
    name_claim = current_app.config.get('NAME_CLAIM', 'name')
    session['oidc_name'] = claims.get(name_claim, '')
    session['oidc_auth_at'] = int(time.time())

    span.add_event(f'{OTEL_NAMESPACE}.user_authenticated', {
        'user.id': claims['sub'],
        'email': claims.get(email_claim, ''),
        'groups': claims.get(groups_claim, []),
        'name': claims.get(name_claim, '')
    })
    return redirect(next_path)


@blueprint.get('/logout')
def logout():
    user = session.get('oidc_user_id', '')
    _set_span_attr('user.id', user)
    session.clear()

    client_id = current_app.config['CLIENT_ID']
    urlsafe_redirect_uri = urllib.parse.quote_plus(
        current_app.config['LOGOUT_REDIRECT_URL']
    )
    logout_url = current_app.config['AUTHORIZATION_SERVER_LOGOUT_URL']
    logout_request = f'{logout_url}?client_id={client_id}' \
        f'&logout_uri={urlsafe_redirect_uri}'

    return redirect(logout_request)


class AuthzResult(enum.Enum):
    ALLOW = 1
    DENY = 2


def deny_all():
    return AuthzResult.DENY


class OidcExtension:

    def __init__(self, app=None, url_prefix='/auth', public_paths=[],
                 authorizer=deny_all):
        self.url_prefix = url_prefix
        self.public_paths = public_paths + [
            f'{self.url_prefix}/login',
            f'{self.url_prefix}/logout',
            f'{self.url_prefix}/oidc'
        ]
        self.authorizer = authorizer
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.jwks_client = jwt.PyJWKClient(app.config['KEYS_URL'])
        app.register_blueprint(blueprint, url_prefix=self.url_prefix)
        app.before_request(self.before_request)
        app.extensions['oidc'] = self

    def redirect_to_login(self):
        return redirect(f'{self.url_prefix}/login?next={request.path}')

    def before_request(self):
        if request.path in self.public_paths:
            return
        if 'oidc_user_id' not in session:
            self.redirect_to_login()

        auth_at = session.get('oidc_auth_at', 0)

        session_exp_mins = current_app.config.get('SESSION_EXPIRY_MINS', 60)
        if auth_at < int(time.time()) - session_exp_mins * 60:
            session.clear()
            self.redirect_to_login()

        last_accessed = session.get('oidc_la', auth_at)
        session_timeout_mins = current_app.config.get('SESSION_TIMEOUT_MINS',
                                                      15)
        if last_accessed < int(time.time()) - session_timeout_mins * 60:
            session.clear()
            return self.redirect_to_login()

        session['oidc_la'] = int(time.time())
        if self.authorizer() != AuthzResult.ALLOW:
            abort(403)


def s256_hash(s):
    h = hashlib.sha256(s.encode('ascii')).digest()
    return base64.urlsafe_b64encode(h).rstrip(b'=').decode('ascii')


def s256_pair():
    s = secrets.token_urlsafe(nbytes=32)
    return s, s256_hash(s)


def s256_match(s, hash):
    return s256_hash(s) == hash
