# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

from requests.auth import AuthBase


class TokenAuth(AuthBase):
    """TODO

    """

    def __init__(self):
        super().__init__()

    def __call__(self, request):
        self._authenticate(request)
        return request

    def _authenticate(self, request):
        """TODO

        :param request:
        :return:
        """

        raise RuntimeError('must be implemented by an inheritor')


class ApplicationAuth(TokenAuth):
    """TODO

    """

    def __init__(self, auth_scope, api_key):
        super().__init__()
        self._auth_scope = auth_scope
        self._api_key = api_key

    def _authenticate(self, request):
        request.headers.update({
            'x-auth-scope': self._auth_scope,
            'x-api-key': self._api_key
        })


class UserAuth(ApplicationAuth):
    """TODO

    """

    def __init__(self, auth_scope, api_key, user_token):
        super().__init__(auth_scope, api_key)
        self._user_token = user_token

    def _authenticate(self, request):
        super()._authenticate(request)
        request.headers['x-auth-token'] = self._user_token


class SSEAuth(ApplicationAuth):
    """TODO

    """

    def __init__(self, auth_scope, api_key, authorization_code):
        super().__init__(auth_scope, api_key)
        self._code = authorization_code

    def _authenticate(self, request):
        super()._authenticate(request)
        request.params['authorization'] = self._code

