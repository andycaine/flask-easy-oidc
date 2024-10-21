from datetime import datetime, timedelta, UTC
import json
import os

import jwt
import jwt.api_jwk
import pytest
import responses
import freezegun
from flask import session
import responses.matchers

import flask_easy_oidc

client_id = 'test_client_id'
client_secret = 'test_client_secret'
redirect_url = 'https://example.com/auth/oidc'
auth_server_login_url = 'https://auth.example.com/login'
auth_server_logout_url = 'https://auth.example.com/logout'
token_endpoint = 'https://auth.example.com/oauth2/token'
state = '5mrYE6Chaf_-yIrf87lzxKEz0XlhGuYHj2udV9Gw2SQ'
state_hash = 'ysEPnUrayvMY6NjGFl5QbD-R4ndmgLrk8iG9NLNUPKU'
code_verifier = 'zzrYE6ChafzzyIrf87lzxKEz0XlhGuYHj2udV9Gw2zz'
code_challenge = 'cAoDcw4JrIj6pOaGRBSiy-rKLUo3-pOJ9Kd4i-RNoFw'
issuer = 'https://cognito-idp.eu-west-1.amazonaws.com/abc'
keys_url = 'https://cognito-idp.eu-west-1.amazonaws.com/abc' \
    '/.well-known/jwks.json'
session_timeout_mins = 60
email_claim = 'test@example.com'
name_claim = 'Test User'
groups_claim = ['Admins']
sub = '26c24244-c0a1-7086-6af4-4b1eaf153b89'


def readrel(filename):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(current_dir, filename), 'r') as f:
        return f.read()


jwks = json.loads(readrel('test_jwks.json'))
private_key = readrel('test_private_key.pem').encode('utf-8')


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv('OIDC_SECRET_KEY', 'super secret')
    monkeypatch.setenv('OIDC_REDIRECT_URL', redirect_url)
    monkeypatch.setenv('OIDC_CLIENT_ID', client_id)
    monkeypatch.setenv('OIDC_CLIENT_SECRET', client_secret)
    monkeypatch.setenv('OIDC_AUTHORIZATION_SERVER_LOGIN_URL',
                       auth_server_login_url)
    monkeypatch.setenv('OIDC_TOKEN_ENDPOINT', token_endpoint)
    monkeypatch.setenv('OIDC_KEYS_URL', keys_url)
    monkeypatch.setenv('OIDC_ISSUER', issuer)
    monkeypatch.setenv('OIDC_LOGOUT_REDIRECT_URL', auth_server_login_url)
    monkeypatch.setenv('OIDC_AUTHORIZATION_SERVER_LOGOUT_URL',
                       auth_server_logout_url)
    monkeypatch.setenv('OIDC_EMAIL_CLAIM', 'email')
    monkeypatch.setenv('OIDC_GROUPS_CLAIM', 'cognito:groups')
    monkeypatch.setenv('OIDC_NAME_CLAIM', 'name')

    def stub_urlopen(request, **_):
        if request.full_url == keys_url:
            return MockHttpResponse(json.dumps(jwks).encode('utf-8'))
        raise Exception('stub_urlopen: Unstubbed URL: ' + request.full_url)

    monkeypatch.setattr('urllib.request.urlopen', stub_urlopen)

    app = flask_easy_oidc.create_app()
    yield app


@pytest.fixture
def client(app):
    yield app.test_client()


@pytest.fixture
def rsps():
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.fixture
def valid_callback_session(client):
    with client.session_transaction() as sess:
        sess['state'] = state
        sess['code_verifier'] = code_verifier
        sess['next_path'] = '/dashboard'


@pytest.fixture
def valid_token_response(rsps):
    yield rsps.post(
        token_endpoint,
        json={
            'id_token': create_id_token()
        },
        status=200
    )


@pytest.fixture
def wrong_aud_token_response(rsps):
    claims = create_claims(aud='something-else')
    yield rsps.post(
        token_endpoint,
        json={
            'id_token': create_id_token(claims=claims)
        },
        status=200
    )


@pytest.fixture
def wrong_iss_token_response(rsps):
    claims = create_claims(iss='something-else')
    yield rsps.post(
        token_endpoint,
        json={
            'id_token': create_id_token(claims=claims)
        },
        status=200
    )


@pytest.fixture
def token_endpoint_failure(rsps):
    yield rsps.post(
        token_endpoint,
        json={},
        status=500
    )


@pytest.fixture
def expired_token_response(rsps):
    five_mins_ago = datetime.now(UTC) - timedelta(minutes=5)
    yield rsps.post(
        token_endpoint,
        json={
            'id_token': create_id_token(
                claims=create_claims(auth_time=five_mins_ago)
            )
        },
        status=200
    )


@pytest.fixture
def tampered_token_response(rsps):
    yield rsps.post(
        token_endpoint,
        json={
            'id_token': create_id_token(
                key_id='Pp+/LoFQ+B11O5+AwuPGlx2OnwFO5McILaXXKZJEfAM='
            )
        },
        status=200
    )


@pytest.fixture
def missing_required_claim_token_response(rsps):
    claims = create_claims()
    del claims['sub']
    yield rsps.post(
        token_endpoint,
        json={
            'id_token': create_id_token(claims=claims)
        },
        status=200
    )


@pytest.fixture
def iat_in_future_token_response(rsps):
    claims = create_claims(auth_time=datetime.now(UTC) + timedelta(minutes=5))
    yield rsps.post(
        token_endpoint,
        json={
            'id_token': create_id_token(claims=claims)
        },
        status=200
    )


def create_claims(auth_time=datetime.now(UTC), aud=client_id, iss=issuer):
    auth_time_ts = int(auth_time.timestamp())
    return {
        'at_hash': 'c5xznp5DMm0DxkAg765i6w',
        'sub': '26c24244-c0a1-7086-6af4-4b1eaf153b89',
        'cognito:groups': groups_claim,
        'iss': iss,
        'origin_jti': 'e5559751-b7e2-430f-b845-ec92ec5a93db',
        'aud': aud,
        'event_id': '17bd50ee-915f-481b-96c7-88ee18c5edda',
        'token_use': 'id',
        'email': email_claim,
        'auth_time': auth_time_ts,
        'name': name_claim,
        'exp': auth_time_ts + 60,
        'iat': auth_time_ts,
        'jti': 'a30f2e59-0b04-469a-942f-1126e9a35bc2'
    }


def create_id_token(key_id='my-test-key',
                    claims=create_claims()):
    algorithm = 'RS256'
    headers = dict(kid=key_id)
    return jwt.encode(claims, private_key, algorithm=algorithm,
                      headers=headers)


class MockHttpResponse:
    def __init__(self, data):
        self.data = data

    def read(self):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


def test_login(client, monkeypatch):
    tokens = [code_verifier, state]
    monkeypatch.setattr('secrets.token_urlsafe', lambda _: tokens.pop())

    with client:
        response = client.get('/auth/login?next=%2Fdashboard')
        assert response.status_code == 302
        assert response.headers['Location'] == (
            f'https://auth.example.com/login?client_id={client_id}'
            '&response_type=code'
            '&code_challenge_method=S256'
            f'&code_challenge={code_challenge}'
            f'&state={state_hash}'
            '&redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Foidc'
        )
        assert session['state'] == state
        assert session['code_verifier'] == code_verifier
        assert session['next_path'] == '/dashboard'


def test_login_with_open_redirect(client):
    response = client.get('/auth/login?next=https%3A%2F%2Fevil.com')
    assert response.status_code == 400


@freezegun.freeze_time()
def test_valid_oidc_callback(client, valid_token_response,
                             valid_callback_session):
    with client:
        response = client.get(f'/auth/oidc?state={state_hash}&code=test_code')
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'
        assert session['oidc_user_id'] == sub
        assert session['oidc_email'] == 'test@example.com'
        assert session['oidc_groups'] == groups_claim
        assert session['oidc_name'] == name_claim
        assert session['oidc_auth_at'] == datetime.now(UTC)
        assert 'state' not in session
        assert 'code_verifier' not in session
        assert 'next_path' not in session

    assert valid_token_response.call_count == 1
    headers = valid_token_response.calls[0].request.headers
    assert headers['Authorization'] == \
        'Basic dGVzdF9jbGllbnRfaWQ6dGVzdF9jbGllbnRfc2VjcmV0'
    assert headers['Content-Type'] == 'application/x-www-form-urlencoded'


def test_oidc_no_state_param(client, valid_callback_session):
    assert client.get('/auth/oidc?code=test_code').status_code == 400


def test_oidc_no_code_param(client, valid_callback_session):
    assert client.get(f'/auth/oidc?state={state}').status_code == 400


def test_oidc_invalid_state_param(client, valid_callback_session):
    assert client.get('/auth/oidc?state=abc&code=test_code').status_code == 400


def test_oidc_csrf_state_defence(client, valid_callback_session):
    another_state_hash = 'xxxxxxrayvMY6NjGFl5QbD-R4ndmgLrk8iG9NLNUPKU'
    assert client.get(f'/auth/oidc?state={another_state_hash}&code=test_code')\
        .status_code == 400


def test_oidc_missing_state_cookie(client, valid_callback_session):
    with client.session_transaction() as sess:
        del sess['state']
    assert client.get(f'/auth/oidc?state={state_hash}&code=test_code')\
        .status_code == 400


def test_oidc_missing_code_verifier(client, valid_callback_session):
    with client.session_transaction() as sess:
        del sess['code_verifier']
    assert client.get(f'/auth/oidc?state={state_hash}&code=test_code')\
        .status_code == 400


def test_oidc_missing_open_redirect(client, valid_callback_session):
    with client.session_transaction() as sess:
        sess['next_path'] = 'https://evil.com'
    assert client.get(f'/auth/oidc?state={state_hash}&code=test_code')\
        .status_code == 400


def test_oidc_token_endpoint_failure(client, valid_callback_session,
                                     token_endpoint_failure):
    assert client.get(f'/auth/oidc?state={state_hash}&code=test_code')\
        .status_code == 401


def test_oidc_expired_token(client, valid_callback_session,
                            expired_token_response):
    assert client.get(f'/auth/oidc?state={state_hash}&code=test_code')\
        .status_code == 401


def test_oidc_tampered_token(client, valid_callback_session,
                             tampered_token_response):
    assert client.get(f'/auth/oidc?state={state_hash}&code=test_code')\
        .status_code == 401


def test_oidc_missing_required_claim(client, valid_callback_session,
                                     missing_required_claim_token_response):
    assert client.get(f'/auth/oidc?state={state_hash}&code=test_code')\
        .status_code == 401


def test_oidc_wrong_aud(client, valid_callback_session,
                        wrong_aud_token_response):
    assert client.get(f'/auth/oidc?state={state_hash}&code=test_code')\
        .status_code == 401


def test_oidc_wrong_iss(client, valid_callback_session,
                        wrong_iss_token_response):
    assert client.get(f'/auth/oidc?state={state_hash}&code=test_code')\
        .status_code == 401


def test_oidc_iat_in_future(client, valid_callback_session,
                            iat_in_future_token_response):
    assert client.get(f'/auth/oidc?state={state_hash}&code=test_code')\
        .status_code == 401


def test_logout(client):
    with client.session_transaction() as sess:
        sess['user_id'] = '26c24244-c0a1-7086-6af4-4b1eaf153b89'
        sess['groups'] = groups_claim
        sess['name'] = name_claim
        sess['iat'] = datetime.now(UTC) + timedelta(minutes=60)
    with client:
        response = client.get('/auth/logout')
        assert response.status_code == 302
        redirect = f'{auth_server_logout_url}' \
            f'?client_id={client_id}' \
            '&logout_uri=https%3A%2F%2Fauth.example.com%2Flogin'
        assert response.headers['Location'] == redirect
        assert list(session.keys()) == []
