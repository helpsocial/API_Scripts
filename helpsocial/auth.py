# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

from requests.auth import AuthBase


class TokenAuth(AuthBase):
    """Base HelpSocial implementation for :class:`requests.auth.AuthBase <AuthBase>`
    which provides token based authentication for api requests from which all
    authentication methods should derive.

    This class should not be created directly.
    """

    def __init__(self):
        super().__init__()

    def __call__(self, request):
        self._authenticate(request)
        return request

    def _authenticate(self, request):
        """Apply the authentication to the request.

        :type request: requests.Request
        :param request: the current request instance
        :rtype requests.Request
        :return: the authenticated request
        """

        raise RuntimeError('must be implemented by an inheritor')


class ApplicationAuth(TokenAuth):
    """Add the application authentication headers, ``x-auth-scope`` and
    ``x-api-key``, to the :class:`requests.Request <requests.Request` object.
    """

    def __init__(self, auth_scope, api_key):
        super().__init__()
        self._auth_scope = auth_scope
        self._api_key = api_key

    def _authenticate(self, request):
        """Set the x-auth-token and x-api-key headers on the request.

        :type request: requests.Request
        :param request: the current request instance
        """
        request.headers.update({
            'x-auth-scope': self._auth_scope,
            'x-api-key': self._api_key
        })


class UserAuth(ApplicationAuth):
    """Add the user authentication header, ``x-auth-token``, to the
    :class:`requests.Request <requests.Request` object in addition to
    the application authentication headers.
    """

    def __init__(self, auth_scope, api_key, user_token):
        super().__init__(auth_scope, api_key)
        self._user_token = user_token

    def _authenticate(self, request):
        """Set the x-auth-token header on the request.

        :type request: requests.Request
        :param request: the current request instance
        """
        super()._authenticate(request)
        request.headers['x-auth-token'] = self._user_token


class SSEAuth(AuthBase):
    """Adds the sse authorization query parameter to the :class:`requests.Request <requests.Request>` object."""

    def __init__(self, authorization_code):
        self._code = authorization_code

    def __call__(self, request):
        """Set the authorization query parameter for the request

        :type request: requests.Request
        :param request: the current request instance
        :rtype requests.Request
        :return: the authenticated request
        """
        request.params['authorization'] = self._code
        return request

