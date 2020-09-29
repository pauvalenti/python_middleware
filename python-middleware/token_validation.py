import jwt
import json
import requests
import base64

from jwt.exceptions import MissingRequiredClaimError
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class InvalidAuthorizationToken(Exception):
    def __init__(self, details):
        super().__init__('Invalid authorization token: ' + details)


def ensure_bytes(key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    return key


def decode_value(val):
    decoded = base64.urlsafe_b64decode(ensure_bytes(val) + b'==')
    return int.from_bytes(decoded, 'big')


def rsa_pem_from_jwk(jwk):
    return RSAPublicNumbers(
        n=decode_value(jwk['n']),
        e=decode_value(jwk['e'])
    ).public_key(default_backend()).public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def get_kid(token):
    headers = jwt.get_unverified_header(token)
    if not headers:
        raise InvalidAuthorizationToken('missing headers')
    try:
        return headers['kid']
    except KeyError:
        raise InvalidAuthorizationToken('missing kid')


def get_jwk(kid):
    jwks = json.loads(requests.get('https://maam-stg.axa.com/maam/v2/jwks').text)
    for jwk in jwks.get('keys'):
        if jwk.get('kid') == kid:
            return jwk
    raise InvalidAuthorizationToken('kid not recognized')


def get_public_key(token):
    return rsa_pem_from_jwk(get_jwk(get_kid(token)))


def check_scope(decoded_token):
    if 'scope' in decoded_token.keys():
        scopes = decoded_token['scope']
        return scopes.split(' ')
    else:
        raise MissingRequiredClaimError('scope')


def get_user_guid(decoded_token):
    if 'axa_guid' in decoded_token.keys():
        guid = decoded_token['axa_guid']
        return guid
    else:
        raise MissingRequiredClaimError('axa_guid')


def validate_jwt(jwt_to_validate, valid_issuer, environment):
    options = {
        'verify_signature': True,
        'verify_exp': True,
        'verify_nbf': True,
        'verify_iat': True,
        'verify_aud': False,
        'verify_iss': True,
        'require_exp': True,
        'require_iat': True,
        'require_nbf': False
    }
    if environment == "test":
        options['verify_signature'] = False
        options['verify_exp'] = False
    # valid_issuer = APP.config['MAAM_URL']
    public_key = get_public_key(jwt_to_validate)
    decoded = jwt.decode(
        jwt=jwt_to_validate,
        key=public_key,
        algorithms=['RS256'],
        issuer=valid_issuer,
        options=options,
    )
    print(decoded)
    return decoded