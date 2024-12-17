from flask import Flask

from .extension import OidcExtension, AuthzResult

__all__ = ['create_app', 'OidcExtension', 'AuthzResult']


def create_app():
    app = Flask(__name__)
    app.config.from_prefixed_env(prefix='OIDC')

    OidcExtension(app=app, url_prefix='/auth')
    return app
