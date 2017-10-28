# Author: Jacob Schofield <jacob@helpsocial.com>
# Copyright (c) 2017 HelpSocial, Inc.
# See LICENSE for details

from functools import wraps


def require_auth(fn):
    """Ensure the function is passed the auth keyword argument.

    :type fn: callable
    :param fn:

    :rtype: callable
    :return:
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'auth' not in kwargs:
            raise RuntimeError('auth required.')
        return fn(*args, **kwargs)
    return wrapper


class Authenticate(object):
    """Decorator ensuring the auth keyword argument is set.

    :type factory: callable
    :param factory: callable returning an AuthBase instance for the request
    """

    def __init__(self, factory):
        self._factory = factory

    def __call__(self, fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if 'auth' not in kwargs or kwargs['auth'] is None:
                try:
                    kwargs['auth'] = self._factory(args[0])
                except TypeError:
                    # The auth factory callable is not an instance
                    # method so let's try to call it without args
                    kwargs['auth'] = self._factory()
            return fn(*args, **kwargs)
        return wrapper
