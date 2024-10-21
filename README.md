# flask-easy-oidc

Create simple invoices.

## Description

`flask-easy-oidc` lets you easily deploy a set of endpoints to integrate with an OIDC-compliant IdP - either as a standalone app or as part of an existing app.

## Getting started

Install using pip:

```bash
pip install flask-easy-oidc
```

Then run as a standalone app:

```bash
flask --app flask_easy_oidc --debug run
```

Or as an extension in an existing app:

```python
from flask import Flask
from flask_easy_oidc import OidcExtension

app = Flask(__name__)

OidcExtension(app=app, url_prefix='/auth')

```
