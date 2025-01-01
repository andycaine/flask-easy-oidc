import enum
import time
import urllib.parse

from flask import redirect, session, request, abort, current_app
import jwt
from opentelemetry import trace
from opentelemetry.semconv._incubating.attributes import user_attributes

from . import blueprint, spanattrs

tracer = trace.get_tracer(__name__)


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
        app.register_blueprint(blueprint.blueprint, url_prefix=self.url_prefix)
        app.before_request(self.authorize)
        app.extensions['oidc'] = self

    def redirect_to_login(self):
        next = urllib.parse.urlparse(f'{request.full_path}')
        if next.netloc:
            # should never happen, but just in case
            redirect(f'{self.url_prefix}/login')
        next_url = urllib.parse.quote_plus(next.geturl())
        return redirect(f'{self.url_prefix}/login?next={next_url}')

    def authorize(self):
        if request.path in self.public_paths:
            return
        if 'oidc_user_id' not in session:
            self.redirect_to_login()

        span = trace.get_current_span()
        span.set_attribute(user_attributes.USER_ID,
                           session.get('oidc_user_id', ''))
        span.set_attribute(user_attributes.USER_EMAIL,
                           session.get('oidc_email', ''))
        span.set_attribute(user_attributes.USER_ROLES,
                           session.get('oidc_groups', []))

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
        auth_result = self.authorizer()
        span.set_attribute(spanattrs.AUTHZ_RESULT, auth_result.name)
        if auth_result != AuthzResult.ALLOW:
            abort(403)
