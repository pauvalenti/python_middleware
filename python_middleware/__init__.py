import json
import re

from .token_validation import get_user_guid, validate_jwt, InvalidAuthorizationToken
from jwt.exceptions import ExpiredSignatureError, MissingRequiredClaimError, InvalidSignatureError
from webob import Request, Response


class middleware():
    '''
    Simple WSGI middleware
    '''
    def __init__(self, maam_url, environment, tenants, app):
        self.maam_url = maam_url
        self.environment = environment
        self.tenants = tenants
        self.app = app

    def check_tenant(self, token_decoded, tenant_id):
        user_guid = get_user_guid(token_decoded)
        isPermited = tenants.is_user_valid(user_guid, tenant_id)
        if isPermited is True:
            return {'code': 200}
        return {'code': 403, 'message': 'Access forbidden.'}

    def validation_token(self, request, tenant_id=None):
        if request.headers.get('Authorization') is not None:
            authorizationHeader = request.headers.get('Authorization')
            try:
                # Validate token
                token = authorizationHeader.split('Bearer ')[1]
                decoded = validate_jwt(token, self.maam_url, self.environment)
            except IndexError:
                return {'code': 400, 'message': 'Invalid token jwt received. Token jwt malformed.'}
            except (ExpiredSignatureError, MissingRequiredClaimError,
                    InvalidSignatureError, InvalidAuthorizationToken) as exc:
                return {'code': 400, 'message': 'Invalid token jwt received. ' + str(exc)}
            except Exception:
                return {'code': 400, 'message': 'Verification failed'}
            else:
                # Validate tenant
                if tenant_id is None:
                    pass
                else:
                    return self.check_tenant(decoded, tenant_id)
                return {'code': 200}
        else:
            return {'code': 401, 'message': 'Authentication is required. Authorization header is missing.'}
        return {'code': 200}

    def validation_json(self, request):
        """"Check if provided data is valid json format"""
        try:
            if request.body:
                if type(json.loads(request.body)) != dict:  # json_data type should be a dict
                    return {'code': 400, 'message': 'Invalid json message received'}
        except json.decoder.JSONDecodeError:
            return {'code': 400, 'message': 'Invalid json message received'}
        else:
            return {'code': 200}

    def validation_headers(self, request):
        """To comply with ASVS 13.1.5. Verify that requests containing unexpected
        or missing content types are rejected with appropriate headers
        (HTTP response status 406 Unacceptable or 415 Unsupported Media Type)."""
        if request.method in ['POST', 'PUT', 'PATCH']:
            content_type = request.headers.get('Content-Type')
            if content_type is not None:
                if content_type == 'application/json':
                    return {'code': 200}
                else:
                    return {'code': 415, 'message': content_type + ' in Content-Type is not valid. Only application/json is allowed'}
            else:
                return {'code': 415, 'message': 'The Content-Type header is missing'}
        else:
            return {'code': 200}

    def __call__(self, environ, start_response):
        request = Request(environ)
        response_headers = [('Content-Type', 'application/json; charset=UTF-8')]
        if request.path.startswith(('/api/version', '/swagger')):
            return self.app(environ, start_response)
        else:
            # Get tenant
            uuid_regex = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            if len(re.findall(uuid_regex, request.path)) > 0 and '/api/tenant/' not in request.path:
                tenant_id = re.findall(uuid_regex, request.path)[0]
            else:
                tenant_id = None
            # Validate token and tenant
            resp_content = self.validation_token(request, tenant_id)
            if resp_content['code'] >= 400:
                res = Response(body=json.dumps(resp_content), headerlist=response_headers, status=resp_content['code'])
                return res(environ, start_response)
            else:
                # Validate headers
                resp_content = self.validation_headers(request)
                if resp_content['code'] >= 400:
                    res = Response(body=json.dumps(resp_content), headerlist=response_headers, status=resp_content['code'])
                    return res(environ, start_response)
                # Validate json
                resp_content = self.validation_json(request)
                if resp_content['code'] >= 400:
                    res = Response(body=json.dumps(resp_content), headerlist=response_headers, status=resp_content['code'])
                    return res(environ, start_response)
                return self.app(environ, start_response)
