# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

from .utils import data_get


class ApiException(Exception):
    """Base class for all HelpSocial Connect Api exceptions."""

    def __init__(self, message, code=None, details=None):
        """
        :type message: string
        :param message: the response message
        :type code: int
        :param code: the response status code
        :type details: dict
        :param details: details for the error response
        """

        self.message = message
        self.code = code
        self.details = details

    @staticmethod
    def make(response):
        """Static factory method which transforms an api error response
        into the proper exception.

        :type response: requests.Response
        :param response: the current response instance
        :rtype ApiException
        :return: the exception instance
        """

        def default_factory(message, errors, code):
            if code >= 500:
                return ServerException(message, code, details=errors)
            return ApiException(message, code, details=errors)

        factories = {
            400: lambda message, details, _: BadRequestException(message,
                                                                 details),
            401: lambda message, details, _: AuthenticationException(message,
                                                                     details),
            403: lambda message, details, _: ForbiddenException(message,
                                                                details),
            404: lambda message, details, _: NotFoundException(message,
                                                               details),
            409: lambda message, details, _: ConflictException(message,
                                                               details),
        }

        content = response.json()
        factory = factories.get(response.status_code, default_factory)

        return factory(
            data_get(content, 'message'),
            data_get(content, 'data'),
            data_get(content, 'status')
        )


class BadRequestException(ApiException):
    """Wraps requests."""

    def __init__(self, message, details=None):
        super().__init__(message, 400, details=details)


class AuthenticationException(ApiException):
    """Wraps requests which failed authentication."""

    def __init__(self, message, details=None):
        super().__init__(message, 401, details=details)


class ForbiddenException(ApiException):
    """Wraps requests which attempted to access a resource without proper permissions."""

    def __init__(self, message, details=None):
        super().__init__(message, 403, details=details)


class NotFoundException(ApiException):
    """Wraps requests which attempted to access a resource that does exist."""

    def __init__(self, message, details=None):
        super().__init__(message, 404, details=details)


class ConflictException(ApiException):
    """Wraps requests creating duplicate resources."""

    def __init__(self, message, details=None):
        super().__init__(message, 409, details=details)


class ServerException(ApiException):
    """Wraps general server error responses."""

    def __init__(self, message, code, details=None):
        super().__init__(message, code, details=details)
