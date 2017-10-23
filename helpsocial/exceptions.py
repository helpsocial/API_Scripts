# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

from .utils import data_get


class ApiException(Exception):
    """
    TODO
    """

    def __init__(self, message, code=None, details=None):
        """
        TODO
        :param message:
        :param code:
        :param details:
        """
        self.message = message
        self.code = code
        self.details = details

    @staticmethod
    def make(response):
        """
        TODO
        :param response:
        :return:
        """
        factories = {
            400: lambda message, errors, _: BadRequestException(message, errors),
            401: lambda message, errors, _: AuthenticationException(message, errors),
            403: lambda message, errors, _: ForbiddenException(message, errors),
            404: lambda message, errors, _: NotFoundException(message, errors),
            409: lambda message, errors, _: ConflictException(message, errors),
            'default': lambda message, errors, code: ApiException(message, code, errors)
        }

        content = response.json()
        factory = factories.get(response.status_code, factories['default'])

        return factory(
            data_get(content, 'message'),
            data_get(content, 'data'),
            data_get(content, 'status')
        )


class BadRequestException(ApiException):
    """
    TODO
    """
    def __init__(self, message, details=None):
        super().__init__(message, 400, details=details)


class AuthenticationException(ApiException):
    """
    TODO
    """
    def __init__(self, message, details=None):
        super().__init__(message, 401, details=details)


class ForbiddenException(ApiException):
    """
    TODO
    """
    def __init__(self, message, details=None):
        super().__init__(message, 403, details=details)


class NotFoundException(ApiException):
    """
    TODO
    """
    def __init__(self, message, details=None):
        super().__init__(message, 404, details=details)


class ConflictException(ApiException):
    """
    TODO
    """
    def __init__(self, message, details=None):
        super().__init__(message, 409, details=details)
