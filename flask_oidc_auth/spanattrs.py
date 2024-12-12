
_OTEL_NAMESPACE = 'flask_oidc_auth'

NEXT_PATH = f'{_OTEL_NAMESPACE}.next_path'

MALICIOUS_REDIRECT = f'{_OTEL_NAMESPACE}.malicious_redirect'

INPUT_VALIDATION_FAIL = f'{_OTEL_NAMESPACE}.input_validation_fail'

MALICIOUS_CSRF = f'{_OTEL_NAMESPACE}.malicious_csrf'

OIDC_TOKEN_ENDPOINT_FAILURE = f'{_OTEL_NAMESPACE}.oidc_token_endpoint_failure'

OIDC_TOKEN_DECODE_FAILURE = f'{_OTEL_NAMESPACE}.oidc_token_decode_failure'

OIDC_TOKEN_UNKNOWN_FAILURE = f'{_OTEL_NAMESPACE}.oidc_token_unknown_failure'

OIDC_CLAIMS = f'{_OTEL_NAMESPACE}.oidc_claims'

USER_AUTHENTICATED = f'{_OTEL_NAMESPACE}.user_authenticated'

AUTHZ_RESULT = f'{_OTEL_NAMESPACE}.authz_result'
