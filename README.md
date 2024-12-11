# flask-oidc-auth

OIDC client endpoints.

## Description

`flask-oidc-auth` lets you easily deploy a set of endpoints to integrate with an OIDC-compliant IdP - either as a standalone app or as part of an existing app.

## Getting started

Install using pip:

```bash
pip install flask-oidc-auth
```

Then run as a standalone app:

```bash
flask --app flask_oidc_auth --debug run
```

Or as an extension in an existing app:

```python
from flask import Flask
from flask_oidc_auth import OidcExtension

app = Flask(__name__)

OidcExtension(app=app, url_prefix='/auth')

```
